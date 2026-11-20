//! Images as docker sees them: a template is an image, its generation's content id the image's id.

use std::io::Read;
use std::sync::Arc;

use crate::image::registry::{blob_path, sha256_hex};
use crate::util::FileStamp;
use serde_json::Value;

use super::Api;
use crate::template::Meta;

const IMAGE_CONFIG_CACHE_MAX: usize = 256;

pub(crate) struct CachedConfig {
    stamp: FileStamp,
    config: Arc<Value>,
}

/// A generation's metadata, if it is here.
pub fn meta(api: &Api, id: &str) -> Option<Meta> {
    crate::template::meta(&api.paths, id)
}

/// The generation the template `name` links to now.
pub fn linked(api: &Api, name: &str) -> Option<String> {
    let link = std::fs::read_link(api.paths.templates.join(name)).ok()?;
    Some(link.file_name()?.to_string_lossy().into_owned())
}

/// What the image's config says of its app (`Env`, `Entrypoint`, `Cmd`, `WorkingDir`, `Labels`, ...), from its
/// config blob while the layer cache keeps it (`system prune` removes it) and it is the one pulled.
pub fn config(api: &Api, meta: &Meta) -> Option<Arc<Value>> {
    let digest = &meta.image.as_ref()?.config_digest;
    let path = blob_path(&api.host.state.join("images/blobs"), digest).ok()?;
    let Ok(metadata) = std::fs::metadata(&path) else {
        api.image_configs.lock().unwrap_or_else(|e| e.into_inner()).remove(&path);
        return None;
    };
    let stamp = FileStamp::of(&metadata);
    {
        let cache = api.image_configs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get(&path).filter(|e| e.stamp == stamp) {
            return Some(entry.config.clone());
        }
    }
    let parsed = (|| -> Option<(FileStamp, Arc<Value>)> {
        let mut file = std::fs::File::open(&path).ok()?;
        let file_stamp = FileStamp::of(&file.metadata().ok()?);
        let mut blob = Vec::with_capacity(file_stamp.len().min(1 << 20) as usize);
        file.read_to_end(&mut blob).ok()?;
        let mut config: Value = serde_json::from_slice(&blob).ok().filter(|_| sha256_hex(&blob) == *digest)?;
        let inner = config.as_object_mut().and_then(|o| o.remove("config")).unwrap_or(Value::Null);
        Some((file_stamp, Arc::new(inner)))
    })();
    let mut cache = api.image_configs.lock().unwrap_or_else(|e| e.into_inner());
    match parsed {
        Some((file_stamp, config)) => {
            if cache.len() >= IMAGE_CONFIG_CACHE_MAX && !cache.contains_key(&path) {
                cache.clear();
            }
            cache.insert(path, CachedConfig { stamp: file_stamp, config: config.clone() });
            Some(config)
        }
        None => {
            cache.remove(&path);
            None
        }
    }
}

pub fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect()
}

/// The app's argv as docker's `Entrypoint` and `Cmd`: the config's, when they are what the template runs
/// (a pull's `--entrypoint` or `--cmd` changed it otherwise); else it is all `Cmd`, as an image without an
/// entrypoint's. The boolean reports whether the config matched the argv.
pub fn app(argv: &[String], config: Option<&Value>) -> (Vec<String>, Vec<String>, bool) {
    if let Some(c) = config {
        let (entrypoint, cmd) = (strings(&c["Entrypoint"]), strings(&c["Cmd"]));
        if entrypoint.iter().chain(&cmd).eq(argv) {
            return (entrypoint, cmd, true);
        }
    }
    (Vec::new(), argv.to_vec(), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_app_splits_as_its_config_does() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let c = json!({"Entrypoint": ["/docker-entrypoint.sh"], "Cmd": ["nginx", "-g", "daemon off;"]});
        let (e, cmd, matched) = app(&argv(&["/docker-entrypoint.sh", "nginx", "-g", "daemon off;"]), Some(&c));
        assert!(matched);
        assert_eq!((e, cmd), (argv(&["/docker-entrypoint.sh"]), argv(&["nginx", "-g", "daemon off;"])));
        // A pull's --cmd: no longer the config's.
        let (e, cmd, matched) = app(&argv(&["/docker-entrypoint.sh", "sh"]), Some(&c));
        assert!(!matched);
        assert_eq!((e, cmd), (vec![], argv(&["/docker-entrypoint.sh", "sh"])));
        assert_eq!(app(&argv(&["sh"]), None), (vec![], argv(&["sh"]), false));
        assert_eq!(app(&[], Some(&json!({"Entrypoint": null, "Cmd": null}))), (vec![], vec![], true));
    }

    #[test]
    fn config_cache_reuses_valid_blobs_and_invalidates_on_change_or_removal() {
        let (_d, api) = super::super::create::tests::fixture();
        let meta = meta(&api, "aaaa1111").unwrap();
        let first = config(&api, &meta).unwrap();
        let second = config(&api, &meta).unwrap();
        assert!(Arc::ptr_eq(&first, &second), "second read should return cached Arc");
        assert_eq!(api.image_configs.lock().unwrap().len(), 1);

        let digest = &meta.image.as_ref().unwrap().config_digest;
        let path = blob_path(&api.host.state.join("images/blobs"), digest).unwrap();

        // Overwriting with corrupt data invalidates the cache.
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(config(&api, &meta).is_none());
        assert!(api.image_configs.lock().unwrap().is_empty());

        // Removing the blob (e.g. system prune) also returns None and clears the cache.
        super::super::create::tests::image(&api, "aaaa1111", json!({"Cmd": ["default"]}));
        let meta = super::meta(&api, "aaaa1111").unwrap();
        assert!(config(&api, &meta).is_some());
        let path = blob_path(&api.host.state.join("images/blobs"), &meta.image.as_ref().unwrap().config_digest).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(config(&api, &meta).is_none());
        assert!(api.image_configs.lock().unwrap().is_empty());
    }
}
