//! Handlers for `rumpel image build` and `rumpel image fetch`.

use anyhow::{bail, Result};

use crate::cli::{ImageBuildCommand, ImageFetchCommand};
use crate::enter::load_and_resolve;
use crate::git::get_repo_root;
use crate::image;

pub fn build(cmd: &ImageBuildCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let (devcontainer, docker_host) = load_and_resolve(&repo_root, cmd.host.as_deref())?;

    let build_opts = match &devcontainer.build {
        Some(b) => b,
        None => bail!(
            "This devcontainer uses 'image', not 'build'.\n\
             Use 'rumpel image fetch' to pull a pre-built image."
        ),
    };

    let result = image::build_devcontainer_image(build_opts, &docker_host, &repo_root, cmd.force)?;

    if result.built {
        println!("Image built: {}", result.image.0);
    } else {
        println!("Image already up to date: {}", result.image.0);
    }

    Ok(())
}

pub fn fetch(cmd: &ImageFetchCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let (devcontainer, docker_host) = load_and_resolve(&repo_root, cmd.host.as_deref())?;

    if devcontainer.build.is_some() {
        bail!(
            "This devcontainer uses 'build', not 'image'.\n\
             Use 'rumpel image build' to build from the Dockerfile."
        );
    }

    let image_name = devcontainer
        .image
        .as_deref()
        .expect("either image or build must be set");

    image::pull_image(image_name, &docker_host)?;
    println!("Image pulled: {}", image_name);

    Ok(())
}
