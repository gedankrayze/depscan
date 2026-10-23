use std::time::Duration;
use tokio::{task::JoinSet, time};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interval_tick_cancellation_and_recreation_on_multithreaded_runtime() {
    const WORKERS: usize = 16;
    const ROUNDS: usize = 64;

    time::timeout(Duration::from_secs(20), async {
        let mut workers = JoinSet::new();
        for _ in 0..WORKERS {
            workers.spawn(async {
                for _ in 0..ROUNDS {
                    let mut interval = time::interval(Duration::from_millis(1));
                    interval.tick().await;
                    // Poll a tick against another timer, then drop the interval.
                    // Both timer-driver completion and tick cancellation are valid.
                    tokio::select! {
                        _ = interval.tick() => {}
                        _ = time::sleep(Duration::from_micros(50)) => {}
                    }
                    drop(interval);
                    tokio::task::yield_now().await;
                }
                let mut control = time::interval(Duration::from_millis(1));
                let first = control.tick().await;
                assert!(control.tick().await > first);
                ROUNDS
            });
        }
        let mut completed = 0;
        while let Some(result) = workers.join_next().await {
            completed += result.expect("interval worker must not panic");
        }
        assert_eq!(completed, WORKERS * ROUNDS);
    })
    .await
    .expect("interval cancellation stress must complete without hanging");
}
