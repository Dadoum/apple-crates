use futures::future::join_all;
use futures::{FutureExt, future::BoxFuture};
use log::warn;
use plist::{Dictionary, Value};
use sha1::Digest as _;
use sha2::Digest as _;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::task::{block_in_place, spawn_blocking};

struct Bundle {
    path: PathBuf,
}

impl Bundle {
    async fn code_resources(&self) -> Dictionary {
        struct CodeResourceFile {
            path: PathBuf,
            sha1: Vec<u8>,
            sha256: Vec<u8>,
        }

        async fn hash_file(relative_path: PathBuf, path: PathBuf) -> CodeResourceFile {
            let file_data = fs::read(&path).unwrap(); // FIXME unwrap
            let file_data2 = file_data.clone();
            let sha1 = spawn_blocking(move || sha1::Sha1::digest(&file_data)[..].into());
            let sha256 = spawn_blocking(move || sha2::Sha256::digest(&file_data2)[..].into());
            CodeResourceFile {
                path: relative_path,
                sha1: sha1.await.unwrap(),
                sha256: sha256.await.unwrap(),
            }
        }

        fn resources_for_directory(
            root: &Path,
            directory: PathBuf,
        ) -> Vec<BoxFuture<'static, CodeResourceFile>> {
            let mut output = Vec::new();
            let mut subfolders = Vec::new();
            if let Ok(read_dir) = fs::read_dir(directory) {
                for entry in read_dir {
                    if let Ok(entry) = entry {
                        let metadata = entry.metadata().expect("metadata call failed");
                        let path = entry.path();
                        if metadata.is_file() {
                            if let Ok(relative_path) = entry.path().strip_prefix(root) {
                                // TODO check rules
                                output.push(hash_file(relative_path.to_path_buf(), path).boxed());
                            } else {
                                warn!("Skipping {:?} as its prefix is not correct", entry.path());
                            }
                        } else if metadata.is_dir() {
                            subfolders.push(resources_for_directory(root, path));
                        }
                    }
                }
            }

            for subfolder in subfolders {
                let data = subfolder;
                output.extend(data);
            }
            output
        }

        let path_buf = self.path.to_path_buf();
        let resources = resources_for_directory(&self.path, path_buf);

        let rules = Dictionary::new();
        let rules2 = Dictionary::new();

        let (files, files2) = {
            let mut files = Dictionary::new();
            let mut files2 = Dictionary::new();

            for res in resources {
                let CodeResourceFile { path, sha1, sha256 } = res.await;

                let path = path.to_string_lossy().into_owned();

                let sha1: Vec<u8> = sha1.into();
                let sha256: Vec<u8> = sha256.into();

                files.insert(path.clone(), Value::Data(sha1.clone()));

                let mut file2 = Dictionary::new();
                file2.insert("hash".to_string(), Value::Data(sha1));
                file2.insert("hash2".to_string(), Value::Data(sha256));

                files2.insert(path, Value::Dictionary(file2));
            }

            (files, files2)
        };

        let code_resources = {
            let mut code_resources = Dictionary::new();
            code_resources.insert("files".to_string(), Value::Dictionary(files));
            code_resources.insert("files2".to_string(), Value::Dictionary(files2));
            code_resources.insert("rules".to_string(), Value::Dictionary(rules));
            code_resources.insert("rules2".to_string(), Value::Dictionary(rules2));

            code_resources
        };

        code_resources
    }

    async fn sign(&self) {
        let code_resources = self.code_resources().await;

        let mut data = Vec::<u8>::new();
        plist::to_writer_xml(&mut data, &code_resources).expect("TODO: panic message");
        println!("{}", String::from_utf8(data).unwrap());
    }
}

#[tokio::main]
async fn main() {
    Bundle {
        path: "/home/dadoum/Téléchargements/YouTube.app/".into(),
    }
    .sign()
    .await;
}
