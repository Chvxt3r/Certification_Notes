# Conda Installation
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

## Init
> Unknown if this needs to be run on MacOS or Windows 

`Init` configures the shell to recognize and utilize conda. Essential for activating environments and using conda commands
```bash
conda init
```
:warning: You may need to restart your shell for the changes to take effect.

After the initial `Init` command, finish with:
```bash
conda config --add channels defaults
conda config --add channels conda-forge
conda config --add channels nvidia # only needed if you are on a PC that has a nvidia gpu
conda config --add channels pytorch
conda config --set channel_priority strict
```
To prevent `conda` from activating base everytime a terminal is opened, run the following:
```bash
conda config --set auto_activate_base false
```
# Managing Virtual Environments
## Create a new VE in conda
```bash
conda create -n <VE name> python=<version>

# Example for this case
conda create -n ai python=3.11
# Creates a VE named ai running python 3.11
```
## Activate the VE
```bash
conda activate <VE name>

# Example for this use case
conda activate ai
```
## Deactivate the VE
```bash
conda deactivate
```
# Essential for this (HTB) use case
:warning: Conda may not include every tool needed. `pip` is still available if a tool is not available in conda
## Core package installation
```bash
conda install -y numpy scipy pandas scikit-learn matplotlib seaborn transformers datasets tokenizers accelerate evaluate optimum huggingface_hub nltk category_encoders

conda install -y pytorch torchvision torchaudio pytorch-cuda=12.4 -c pytorch -c nvidia

pip install requests requests_toolbelt
```
# Updating Conda
```bash
conda update --all
```

# JupyterLab
## Installation
Use `conda` to install
```bash
conda install -y jupyter jupyterlab notebook ipykernel 
```
:warning: Make sure you are in your virtual environment
## Running
Fromw within your virtual environment:
```bash
jupyter lab
```
Opens in a browser
:warning: Obviously this will not work over ssh, unless you are accessing from another computer.

> URL for accessing Jupyter Lab: `http://<host/IP>:8888

:warning: If access from another computer, you will need the token from the startup messaging, and then you can set a password


