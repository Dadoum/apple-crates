use crate::backend::{BackendError, BackendResult};
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use std::future::Future;
use std::sync::{mpsc as std_mpsc, OnceLock};

type BackendJob = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone)]
struct BackendWorker {
    sender: mpsc::UnboundedSender<BackendJob>,
}

static BACKEND_WORKER: OnceLock<BackendResult<BackendWorker>> = OnceLock::new();
static SEND_RUNTIME: OnceLock<BackendResult<tokio::runtime::Runtime>> = OnceLock::new();

pub(crate) async fn run<T, F, M>(label: &'static str, make_future: M) -> Result<T, BackendError>
where
    T: Send + 'static,
    F: Future<Output = T> + 'static,
    M: FnOnce() -> F + Send + 'static,
{
    let worker = worker(label)?;

    let (sender, receiver) = oneshot::channel();
    worker
        .sender
        .unbounded_send(Box::new(move || {
            tokio::task::spawn_local(async move {
                let value = make_future().await;
                let _ = sender.send(value);
            });
        }))
        .map_err(|_| BackendError::TaskCanceled { label })?;

    receiver
        .await
        .map_err(|_| BackendError::TaskCanceled { label })
}

pub(crate) async fn run_send<T, F>(label: &'static str, future: F) -> Result<T, BackendError>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let runtime = send_runtime(label)?;
    let (sender, receiver) = oneshot::channel();
    runtime.spawn(async move {
        let _ = sender.send(future.await);
    });

    receiver
        .await
        .map_err(|_| BackendError::TaskCanceled { label })
}

// Build large I/O futures on the runtime thread, not on the UI thread's stack.
pub(crate) async fn run_send_with<T, F, M>(
    label: &'static str,
    make_future: M,
) -> Result<T, BackendError>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
    M: FnOnce() -> F + Send + 'static,
{
    let runtime = send_runtime(label)?;
    let (sender, receiver) = oneshot::channel();
    runtime.spawn(async move {
        let _ = sender.send(Box::pin(make_future()).await);
    });
    receiver
        .await
        .map_err(|_| BackendError::TaskCanceled { label })
}

fn worker(label: &'static str) -> BackendResult<BackendWorker> {
    match BACKEND_WORKER.get_or_init(start_worker) {
        Ok(worker) => Ok(worker.clone()),
        Err(error) => Err(BackendError::Message(format!(
            "Failed to start backend runtime for {label}: {}",
            error.user_message()
        ))),
    }
}

fn start_worker() -> BackendResult<BackendWorker> {
    let (job_sender, mut job_receiver) = mpsc::unbounded::<BackendJob>();
    let (init_sender, init_receiver) = std_mpsc::channel::<BackendResult<()>>();

    std::thread::Builder::new()
        .name("super-sideloader-backend".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => {
                    let _ = init_sender.send(Ok(()));
                    runtime
                }
                Err(error) => {
                    let _ = init_sender.send(Err(BackendError::Message(error.to_string())));
                    return;
                }
            };

            let local = tokio::task::LocalSet::new();
            local.block_on(&runtime, async move {
                while let Some(job) = job_receiver.next().await {
                    job();
                }
            });
        })
        .map_err(|source| BackendError::Command {
            action: "Start backend runtime thread",
            source,
        })?;

    match init_receiver.recv() {
        Ok(Ok(())) => Ok(BackendWorker { sender: job_sender }),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(BackendError::Message(error.to_string())),
    }
}

fn send_runtime(label: &'static str) -> BackendResult<&'static tokio::runtime::Runtime> {
    match SEND_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("super-sideloader-io")
            .build()
            .map_err(|error| BackendError::Message(error.to_string()))
    }) {
        Ok(runtime) => Ok(runtime),
        Err(error) => Err(BackendError::Message(format!(
            "Failed to start backend runtime for {label}: {}",
            error.user_message()
        ))),
    }
}
