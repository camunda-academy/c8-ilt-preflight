//go:build windows

package launcher

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// Killing a timed-out probe on Windows must reach the WHOLE process tree, not
// just the one process os/exec tracks. run.cmd's own process is a thin batch
// shell -- the real work (dotnet.exe, mvn's javaw.exe, python.exe, node.exe)
// runs as its children, invoked via `call`. Terminating only the tracked
// cmd.exe leaves those orphaned and running to their own natural completion,
// unaffected by the timeout: the script logic that would translate their
// eventual result into a JSON fragment is already dead, so the run reports a
// bare crash with no diagnostic detail even though the real cause (e.g. a
// dependency-resolution timeout) was perfectly explainable.
//
// A Windows Job Object solves this atomically: every process assigned to it,
// and every child THEY spawn afterward (inherited automatically unless a
// process explicitly opts out), dies together on TerminateJobObject, with no
// window for a grandchild to slip out before it can be reached individually.
//
// Implemented via raw syscall against kernel32.dll, not golang.org/x/sys/windows:
// this binary is built with no external modules and no CGO so a customer
// security team can audit the source and reproduce the build, and this is the
// only Job Object usage the tool needs.
var (
	modkernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW      = modkernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObj  = modkernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObj = modkernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject    = modkernel32.NewProc("TerminateJobObject")
)

// jobObjectExtendedLimitInformation is the JOBOBJECTINFOCLASS value for
// JobObjectExtendedLimitInformation (winnt.h).
const jobObjectExtendedLimitInformation = 9

// jobObjectLimitKillOnJobClose (winnt.h) makes Windows kill every remaining
// member process the moment the LAST handle to the job is closed -- a safety
// net so a bug in this program's own cleanup path can never leave a
// grandchild running past this probe's own lifetime.
const jobObjectLimitKillOnJobClose = 0x00002000

// Field layout mirrors the real Win32 structs exactly (same types, same
// order), which on amd64 reproduces the C compiler's own alignment padding —
// e.g. the 4 bytes between LimitFlags (uint32) and MinimumWorkingSetSize
// (uintptr) that SIZE_T's 8-byte alignment forces in the real struct.
type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// processTreeKiller holds the two handles a Job Object needs kept alive for
// the probe's lifetime: the job itself, and the duplicate process handle
// AssignProcessToJobObject requires (PROCESS_SET_QUOTA|PROCESS_TERMINATE) --
// distinct from whatever handle os/exec keeps internally, since that one
// isn't exposed to callers.
type processTreeKiller struct {
	job     syscall.Handle
	process syscall.Handle
}

// configureSysProcAttr is a no-op on Windows: Job Object membership is set up
// after Start() (see newProcessTreeKiller), and needs no CreationFlags set
// beforehand.
func configureSysProcAttr(cmd *exec.Cmd) {}

// newProcessTreeKiller creates an anonymous Job Object, assigns cmd's already-
// started process to it, and returns a kill function that terminates every
// process the job still contains, plus a cleanup function that must run once
// the probe has finished (successfully or not) to release both handles.
//
// Errors here are deliberately non-fatal to the probe itself: if job-object
// setup fails (an unexpected, locked-down environment), the fallback kill is
// still cmd.Process.Kill() on the tracked process alone -- worse than the
// tree-kill this exists to provide, but no worse than the tool's prior
// behavior, so a probe that would otherwise have run fine must not fail
// outright just because this defense-in-depth layer couldn't set up.
func newProcessTreeKiller(cmd *exec.Cmd) (kill func() error, cleanup func()) {
	fallback := func() error { return cmd.Process.Kill() }
	noopCleanup := func() {}

	jobHandle, _, _ := procCreateJobObjectW.Call(0, 0)
	if jobHandle == 0 {
		return fallback, noopCleanup
	}
	job := syscall.Handle(jobHandle)

	info := jobObjectExtendedLimitInfo{
		BasicLimitInformation: jobObjectBasicLimitInformation{
			LimitFlags: jobObjectLimitKillOnJobClose,
		},
	}
	ok, _, _ := procSetInformationJobObj.Call(
		uintptr(job),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if ok == 0 {
		syscall.CloseHandle(job)
		return fallback, noopCleanup
	}

	// A fresh handle via OpenProcess, not whatever os/exec holds internally --
	// that one is never exposed to callers. PROCESS_SET_QUOTA is the specific
	// access right AssignProcessToJobObject documents as required, alongside
	// PROCESS_TERMINATE for the eventual TerminateJobObject.
	const processSetQuota = 0x0100
	const processTerminate = 0x0001
	procHandle, err := syscall.OpenProcess(processSetQuota|processTerminate, false, uint32(cmd.Process.Pid))
	if err != nil {
		syscall.CloseHandle(job)
		return fallback, noopCleanup
	}

	assigned, _, _ := procAssignProcessToJobObj.Call(uintptr(job), uintptr(procHandle))
	if assigned == 0 {
		syscall.CloseHandle(procHandle)
		syscall.CloseHandle(job)
		return fallback, noopCleanup
	}

	k := &processTreeKiller{job: job, process: procHandle}
	kill = func() error {
		// cmd.Cancel returning nil tells os/exec "handled" -- it never falls
		// back to its own default Kill() once Cancel is set, so a silently
		// swallowed failure here would leave the process running with nothing
		// left to catch it. Checking the result and falling back to the
		// tracked process alone is strictly better than declaring success on
		// a call that may not have actually terminated anything.
		//
		// The discarded second/third return values from .Call() are NOT an
		// error-nil-check target here: LazyProc.Call always populates the
		// third value from GetLastError win-or-lose, so it's meaningless
		// unless the primary (first) return already reported failure.
		if terminated, _, _ := procTerminateJobObject.Call(uintptr(k.job), 1); terminated != 0 {
			return nil
		}
		return cmd.Process.Kill()
	}
	cleanup = func() {
		syscall.CloseHandle(k.process)
		syscall.CloseHandle(k.job)
	}
	return kill, cleanup
}
