//! Handlers for `rumpel image build` and `rumpel image fetch`.

use anyhow::Result;

use crate::cli::{ImageBuildCommand, ImageFetchCommand};
use crate::config::Host;
use crate::enter::load_and_resolve;
use crate::git::get_repo_root;
use crate::image::{self, BuildFlags};

pub fn build(cmd: &ImageBuildCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let (devcontainer, docker_host, _default_image_dir) =
        load_and_resolve(&repo_root, cmd.host_args.resolve()?)?;

    let build_opts = match &devcontainer.build {
        Some(b) => b,
        None => {
            return Err(anyhow::anyhow!(
                "This devcontainer uses 'image', not 'build'.\n\
             Use 'rumpel image fetch' to pull a pre-built image."
            ))
        }
    };

    let flags = BuildFlags {
        no_cache: cmd.no_cache,
        pull: cmd.pull,
    };

    let on_output: Option<image::BuildOutputFn> =
        Some(Box::new(|line: image::OutputLine| match line {
            image::OutputLine::Stdout(s) => println!("{s}"),
            image::OutputLine::Stderr(s) => eprintln!("{s}"),
        }));

    if matches!(docker_host, Host::Kubernetes { registry: None, .. }) {
        return Err(anyhow::anyhow!(
            "Building images for Kubernetes requires a registry.\n\
             Set 'registry' in the [k8s] section of .rumpelpod.toml, \
             or use --k8s-registry."
        ));
    }

    let build_host = match docker_host {
        Host::Kubernetes { .. } => &Host::Localhost,
        ref other => other,
    };

    let result = image::build_devcontainer_image(
        build_opts, build_host, &repo_root, &flags, on_output, None,
    )?;

    if let Host::Kubernetes {
        registry: Some(ref registry),
        ..
    } = docker_host
    {
        let dest = image::push_to_registry(&result.image.0, registry)?;
        println!("Image built and pushed: {dest}");
        return Ok(());
    }

    let image = &result.image.0;
    println!("Image built: {image}");

    Ok(())
}

pub fn fetch(cmd: &ImageFetchCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let (devcontainer, docker_host, _default_image_dir) =
        load_and_resolve(&repo_root, cmd.host_args.resolve()?)?;

    if devcontainer.build.is_some() {
        return Err(anyhow::anyhow!(
            "This devcontainer uses 'build', not 'image'.\n\
             Use 'rumpel image build' to build from the Dockerfile."
        ));
    }

    if matches!(docker_host, Host::Kubernetes { .. }) {
        return Err(anyhow::anyhow!(
            "'rumpel image fetch' is not supported for Kubernetes hosts.\n\
             Images are pulled directly by the cluster."
        ));
    }

    let image_name = devcontainer
        .image
        .as_deref()
        .expect("either image or build must be set");

    image::pull_image(image_name, &docker_host, None)?;
    println!("Image pulled: {image_name}");

    Ok(())
}
