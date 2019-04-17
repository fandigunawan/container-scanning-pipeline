# Gitlab Installation Instructions
1). Edit `gitlab_install.sh` and replace the `<URL_HERE>` tag with your external Url. (typically ec2 public dns or elb)

        vi gitlab_install.sh
2). Install gitlab initially by running the `gitlab_install.sh` script:

         ./gitlab_install.sh
3). Verify gitlab is stood up:

        sudo gitlab-ctl status

### Optional:
##### Integrate IDM
1).Edit `freeipa_settings.yml` and insert the following information needed on proper lines:

         host: <IP ADDRESS HERE>
        password: <PASSWORD HERE>
2). Edit the installed gitlab configuration:

        sudo vi /etc/gitlab/gitlab.rb
Replace the following:

        # gitlab_rails['ldap_enabled'] = false
With:
        
        gitlab_rails['ldap_enabled'] = true
        gitlab_rails['ldap_servers'] = YAML.load_file('/etc/gitlab/freeipa_settings.yml')
