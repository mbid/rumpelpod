//! Handlers for `rumpel image build` and `rumpel image fetch`.

use anyhow::Result;

use crate::cli::{ImageBuildCommand, ImageFetchCommand};
use crate::config::Host;
use crate::enter::load_and_resolve;
use crate::git::get_repo_root;
use crate::image::{self, BuildFlags};

pub fn build(cmd: &ImageBuildCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let (devcontainer, docker_host) = load_and_resolve(&repo_root, cmd.host_args.resolve()?)?;

    let build_opts = match &devcontainer.build {
        Some(b) => b,
        None => {
            return Err(anyhow::anyhow!(
                "This devcontainer uses 'image', not 'build'.\n\
             Use 'rumpel image fetch' to pull a pre-built image."
            ))
        }
    };

    // K8s has no Docker daemon -- build against the local daemon instead.
    let build_host = match &docker_host {
        Host::Kubernetes { .. } => &Host::Localhost,
        other => other,
    };

    let flags = BuildFlags {
        no_cache: cmd.no_cache,
        pull: cmd.pull,
    };

    let on_output: Option<image::BuildOutputFn> =
        Some(Box::new(|line: image::OutputLine| match line {
            image::OutputLine::Stdout(s) => println!("{}", s),
            image::OutputLine::Stderr(s) => eprintln!("{}", s),
        }));
    let result =
        image::build_devcontainer_image(build_opts, build_host, &repo_root, &flags, on_output)?;
    println!("Image built: {}", result.image.0);

    // For K8s with a registry, push the built image
    if let Host::Kubernetes {
        registry: Some(ref push_reg),
        ref pull_registry,
        ..
    } = docker_host
    {
        let pull_reg = pull_registry.as_deref().unwrap_or(push_reg);
        let on_push: Option<image::BuildOutputFn> =
            Some(Box::new(|line: image::OutputLine| match line {
                image::OutputLine::Stdout(s) => println!("{}", s),
                image::OutputLine::Stderr(s) => eprintln!("{}", s),
            }));
        let pushed = image::push_to_registry(&result.image, push_reg, pull_reg, on_push)?;
        println!("Image pushed: {}", pushed.0);
    }

    Ok(())
}

pub fn fetch(cmd: &ImageFetchCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let (devcontainer, docker_host) = load_and_resolve(&repo_root, cmd.host_args.resolve()?)?;

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

    image::pull_image(image_name, &docker_host)?;
    println!("Image pulled: {}", image_name);

    Ok(())
}
