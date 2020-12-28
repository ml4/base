build:
	@. init.sh

clean:
	@read -p "Have you deleted any test VMs and SSH keypair from AWS (yes ? ^C && attend the AWS console : <enter>)?" NULL
	@rm -rf base_unit_test_key base_unit_test_key.pub main.tf .terraform .terraform.lock.hcl terraform.tfstate u18.box preseed.cfg role-policy.json output-virtualbox-iso 2>/dev/null
