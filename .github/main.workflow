workflow "Build and Test" {
  resolves = ["Test"]
  on = "push"
}

action "Build" {
  uses = "actions/npm@master"
  args = "install"
}

action "Test" {
  needs = "Build"
  uses = "actions/npm@master"
  args = "test"
}

workflow "Publish on NPM" {
  on = "release"
  resolves = ["Publish"]
}

action "Publish" {
  uses = "actions/npm@master"
  args = "publish"
  secrets = ["NPM_AUTH_TOKEN"]
}
