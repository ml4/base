build:
	@./run.sh

clean:
	@terraform destroy -auto-approve
	@rm -rf baseUnitTestKey baseUnitTestKey.pub baseUnitTest.tf .terraform .terraform.lock.hcl terraform.tfstate* u18.box preseed.cfg rolePolicy.json output-virtualbox-iso 2>/dev/null
