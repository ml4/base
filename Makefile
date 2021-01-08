build:
	@./run.sh

clean:
	@echo "Remember to delete any test VMs/volumes/snapshots and SSH keypairs from AWS!"
	@echo
	@rm -rf baseUnitTestKey baseUnitTestKey.pub baseUnitTest.tf .terraform .terraform.lock.hcl terraform.tfstate u18.box preseed.cfg rolePolicy.json output-virtualbox-iso 2>/dev/null
