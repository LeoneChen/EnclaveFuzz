use libafl::{
    corpus::InMemoryOnDiskCorpus,
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{HavocScheduledMutator, havoc_mutations},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver},
    schedulers::StdScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    AsSliceMut,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::tuple_list,
};

pub fn main() {
    const MAP_SIZE: usize = 65536;
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    unsafe { shmem.write_to_env("__AFL_SHM_ID").unwrap() };
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem.as_slice_mut()))
            .track_indices()
    };

    // feedback
    let mut feedback = MaxMapFeedback::new(&edges_observer);
    let mut objective = CrashFeedback::new();

    // State
    let mut state = StdState::new(
        StdRand::new(),
        InMemoryOnDiskCorpus::new("/tmp/curpus").unwrap(),
        InMemoryOnDiskCorpus::new("/tmp/crash").unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    // Fuzzer
    let scheduler = StdScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Basic utils
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let mut harness = |_input: &BytesInput| {
        std::env::set_current_dir("/tmp/workdir").unwrap();
        unsafe { std::env::set_var("AFL_MAP_SIZE", MAP_SIZE.to_string()) };
        ExitKind::Ok
    };

    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        std::time::Duration::from_secs(60),
    )
    .unwrap();

    // Load initial corpus
    // assum only one input in the initial corpus, so needn't reset db_file_linux and db_file_gramine after each seed is evaluated
    state
        .load_initial_inputs(
            &mut fuzzer,
            &mut executor,
            &mut mgr,
            &[std::path::PathBuf::from("/tmp/corpus")],
        )
        .unwrap();

    // Start fuzzing
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .unwrap();
}
