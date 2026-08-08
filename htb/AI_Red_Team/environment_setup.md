# Installation
## Windows
Install Scoop
```powershell
Set-ExecutionPolicy RemoteSigned -scope CurrentUser # Allow scripts to run

irm get.scoop.sh | iex
```
Add the `extras` bucket containing miniconda
```powershell
scoop bucket add extras
```
Install `miniconda`
```powershell
scoop install miniconda3
```
Verify
```powershell
conda --version
```

## MacOS
Install `Homebrew`
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```
Install `Miniconda`
```
brew install --cask miniconda
```
Verify
```
conda --version
```
## Linux
Can install miniconda direct
```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh

chmod +x Miniconda3-latest-Linux-x86_64.sh

./Miniconda3-latest-Linux-x86_64.sh -b -u

eval "$(/home/$USER/miniconda3/bin/conda shell.$(ps -p $$ -o comm=) hook)"
```
Verify
```bash
conda --version
```
