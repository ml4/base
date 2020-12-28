build:
	@./run.sh

clean:
	@echo "Remember to delete any test VMs/volumes/snapshots and SSH keypairs from AWS!"
	@echo
	@rm -rf base_unit_test_key base_unit_test_key.pub main.tf .terraform .terraform.lock.hcl terraform.tfstate u18.box preseed.cfg role-policy.json output-virtualbox-iso 2>/dev/null
