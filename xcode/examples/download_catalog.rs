use xcode::downloads::{ComponentKind, DownloadCatalog, DownloadSource};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = match std::env::args_os().nth(1) {
        Some(path) => DownloadCatalog::from_bytes(&std::fs::read(path)?)?,
        None => DownloadCatalog::fetch(&reqwest::Client::new()).await?,
    };
    println!(
        "{} simulator runtimes, {} components; refresh after {} seconds",
        catalog.simulators.len(),
        catalog.components.len(),
        catalog.refresh_interval,
    );
    for component in &catalog.components {
        if component.kind != ComponentKind::DeviceSupport {
            continue;
        }
        println!("{} (build {})", component.download.name, component.build);
        match &component.download.source {
            DownloadSource::Direct(url) => println!("  {url}"),
            DownloadSource::MobileAsset => println!("  Requires MobileAsset resolution"),
        }
    }
    Ok(())
}
