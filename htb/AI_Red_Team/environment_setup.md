# AI Environment Setup

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
