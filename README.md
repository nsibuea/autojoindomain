# autojoindomain
AWS User Data script for windows server to be able to automatically join domain
1. Create aws IAM policy with the detail on role.json
2. Create aws role, attache the policy from the step 1
3. add other aws default policy required by ec2 such as AmazonSSMManagedInstanceCore, CloudWatchAgentAdminPolicy, AmazonEC2RoleforSSM
4. create secret manager named prod/AD
5. add the following secret key: UserID, PAssword, Domain, oupath, localpwd and their secret value to the secret manager.
6. on EC2 instance AMI, add the
