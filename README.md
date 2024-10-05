# rbw-ansible

Ansible lookup plugin for rbw client (https://github.com/doy/rbw). Alpha status.

See `rbw.py` pydoc documentation for usage.


## Usage

Checkout project in `$SOMEDIR/` folder.

Invoke with lookup module :

```
# unlock rbw
rbw unlock
# Invoke with ansible
ANSIBLE_LOOKUP_PLUGINS=£SOMEDIR/ ansible -vvv -m debug -a "msg={{ lookup('rbw', 'Name') }}" localhost
```
