use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_dir = manifest_dir
        .parent()
        .expect("backend must live under the workspace root")
        .to_path_buf();
    let frontend_dir = repo_dir.join("frontend");
    let frontend_dist = frontend_dir.join("dist");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let embedded_dist = out_dir.join("frontend-dist");

    println!("cargo:rerun-if-env-changed=SSO_SKIP_FRONTEND_BUILD");
    for file in [
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "vite.config.ts",
        "index.html",
    ] {
        print_rerun_for(&frontend_dir.join(file));
    }
    print_rerun_for(&frontend_dir.join("src"));

    if env::var("SSO_SKIP_FRONTEND_BUILD").ok().as_deref() != Some("1") {
        ensure_frontend_dependencies(&frontend_dir);
        run(&frontend_dir, "npm", &["run", "build"]);
    } else if !frontend_dist.exists() {
        panic!("SSO_SKIP_FRONTEND_BUILD=1 was set, but frontend/dist does not exist");
    }

    reset_dir(&embedded_dist).expect("failed to reset embedded frontend output dir");
    copy_dir(&frontend_dist, &embedded_dist).expect("failed to copy frontend dist");
    generate_assets_rs(&embedded_dist, &out_dir.join("frontend_assets.rs"))
        .expect("failed to generate embedded frontend asset table");
}

fn ensure_frontend_dependencies(frontend_dir: &Path) {
    if frontend_dir.join("node_modules").exists() {
        return;
    }
    if frontend_dir.join("package-lock.json").exists() {
        run(frontend_dir, "npm", &["ci", "--no-audit", "--fund=false"]);
    } else {
        run(
            frontend_dir,
            "npm",
            &["install", "--no-audit", "--fund=false"],
        );
    }
}

fn run(cwd: &Path, program: &str, args: &[&str]) {
    let status = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|err| panic!("failed to run {program}: {err}"));
    if !status.success() {
        panic!("{program} {} failed with status {status}", args.join(" "));
    }
}

fn print_rerun_for(path: &Path) {
    if !path.exists() {
        return;
    }
    let name = path.file_name().and_then(|value| value.to_str());
    if matches!(name, Some("node_modules" | "dist")) {
        return;
    }
    println!("cargo:rerun-if-changed={}", path.display());
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let child = entry.path();
            if child.is_dir() {
                print_rerun_for(&child);
            } else {
                println!("cargo:rerun-if-changed={}", child.display());
            }
        }
    }
}

fn reset_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)
}

fn copy_dir(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        if source.is_dir() {
            copy_dir(&source, &target)?;
        } else {
            fs::copy(source, target)?;
        }
    }
    Ok(())
}

fn generate_assets_rs(dist: &Path, output: &Path) -> io::Result<()> {
    let mut files = Vec::new();
    collect_files(dist, dist, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut source = String::from(
        "pub struct EmbeddedAsset {\n    pub path: &'static str,\n    pub mime: &'static str,\n    pub bytes: &'static [u8],\n}\n\npub static ASSETS: &[EmbeddedAsset] = &[\n",
    );
    for (relative, absolute) in files {
        source.push_str("    EmbeddedAsset { path: ");
        source.push_str(&rust_string(&relative));
        source.push_str(", mime: ");
        source.push_str(&rust_string(mime_for(&relative)));
        source.push_str(", bytes: include_bytes!(");
        source.push_str(&rust_string(&absolute.display().to_string()));
        source.push_str(") },\n");
    }
    source.push_str("];\n");
    fs::write(output, source)
}

fn collect_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("asset should be under dist root")
                .to_string_lossy()
                .replace('\\', "/");
            files.push((relative, path));
        }
    }
    Ok(())
}

fn rust_string(value: &str) -> String {
    format!("{value:?}")
}

fn mime_for(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|value| value.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}
