### AnyKernel3 Ramdisk Mod Script
## osm0sis @ xda-developers
##
## File ini di-commit di repo (bukan di-generate inline oleh CI) supaya
## isinya bisa di-audit lewat git dan tidak rentan rusak karena indentasi
## heredoc di dalam YAML.
##
## Target   : Samsung Galaxy M51 (SM-M515F, SM7150 / sdmmagpie)
## Recovery : TWRP
## Boot     : non-A/B, non-slot

### AnyKernel setup
# begin properties
properties() { '
kernel.string=ReSukiSU Kernel for Samsung Galaxy M51 (SM-M515F, SM7150)
do.devicecheck=1
do.modules=0
do.systemless=1
do.cleanup=1
do.cleanuponabort=0
device.name1=m51
device.name2=m51eur
device.name3=SM-M515F
device.name4=
device.name5=
supported.versions=
supported.patchlevels=
'; } # end properties

### AnyKernel install
# begin attributes
attributes() {
set_perm_recursive 0 0 755 644 $ramdisk/*;
set_perm_recursive 0 0 750 750 $ramdisk/init* $ramdisk/sbin;
} # end attributes

## boot shell variables
block=/dev/block/bootdevice/by-name/boot;
is_slot_device=0;
ramdisk_compression=auto;
patch_vbmeta_flag=auto;

# import functions/variables and setup patching - see for reference (DO NOT REMOVE)
. tools/ak3-core.sh && attributes;

# boot install
dump_boot;
write_boot;
## end boot install
