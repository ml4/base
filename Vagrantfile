# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.require_version ">= 2.2.9"
VAGRANTFILE_API_VERSION = "2"
VAGRANT_FORCE_COLOR = "1"
Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
	config.vm.provider "virtualbox" do |v|
#    v.gui = true
		v.memory = 2048
	end
	config.vm.box = "u18"
	config.vm.define "box" do |box|
  	box.vm.hostname = "base"
	end
	config.vm.synced_folder ".", "/home/ubuntu", type: "rsync", rsync__args: ["--verbose", "--archive", "--delete", "-z"]
end
