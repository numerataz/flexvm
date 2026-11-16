These GPL fixtures run only in the guest. Build them independently against the
matching packaged `/lib/modules/$(uname -r)/build` inputs:

```sh
make -C /lib/modules/$(uname -r)/build M="$PWD" modules
make -C /lib/modules/$(uname -r)/build M="$PWD" modules_install
depmod -a
modprobe flexvm_test_device
cat /dev/flexvm-module-test
```

`flexvm_test_device` depends on an exported symbol from `flexvm_test_state`.
The device reads the state's random cookie and a kernel timer counter. The
cookie is created inside the module on each load; it cannot be reproduced by
restarting the userspace test. Across a VM restore, the cookie must match and
the timer must make fresh progress. Unloading the state module while the
device module depends on it must fail. After unloading the device and state,
the device and both sysfs module entries must disappear.

`scripts/compat/software-modules.py` exercises normal CLI bundle injection,
guest compilation, DKMS, dependency handling, vermagic rejection and loaded
module state through software pause/unpause and stop/start. It masks and traces
host virtualization devices and host module-loading syscalls. Native x86_64 and
aarch64 CI run this test independently.

The `kernel_modules` case in `scripts/e2e.py` builds the same fixtures against
the SDK, then checks loaded state through accelerated pause, suspend,
checkpoint/restore and migration in both directions. Its static `module-control`
helper runs only inside the guest.
