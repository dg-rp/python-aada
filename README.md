# Azure AD AWS Cli Authentication

Generates STS Tokens based on SAML Assertion from Azure AD (with MFA enabled also). This fork is modified to work specifically with my own use case.


# System Requirements

* Python3.7+

I use this script with python 3.7 installed with homebrew. You might have luck with other methods but this article's scope is limited to 3.7 via homebrew. If you're running Linux on your laptop you'll follow a similar path but you would likely be using yum or apt.

# Installing Python3.7 with homebrew
Run the following commands to check what version of python you're running and install at least python 3.7.

Commands
```bash
$ python --version
```
If the above command doesn't return python 3.7, you can run the following, otherwise skip to installing pip.

If you do need to install python 3.7, do so by first installing brew.

Commands
```bash
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
$ brew install python@3.7
```
Then add an alias to your ~/.bash_profile file or the profile file for whatever shell you're using.

Commands
```bash
$ python_path=$(which python3)
$ echo "alias python='${python_path}'" >> ~/.bash_profile
$ source ~/.bash_profile
```

# Installing pip
Now that you're running at least python 3.7 you can install pip.

Commands
```bash
$ python --version
```
Python 3.7.7
```bash
$ curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
$ python get-pip.py
```

# Installing python script
Run the following commands to install and configure.

Commands
```bash
pip install git+https://github.com/dg-rp/python-aada.git -r https://raw.githubusercontent.com/dg-rp/python-aada/master/requirements.txt
```
