#! /usr/bin/env bash

## GLOBAL VARIABLES ##
args=$@
exit_code=0
tos=1 ## TIME TO SLEEP
all=0

chp="" # chapter
catid="" # categories id
level=0
result=Fail

declare -a excl_arr1
declare -a excl_arr2

## DECLARING THE DIRECTORIES ##
LOG_DIR="/home/sbouchex/cis_audit"

FILE=$(basename $0|tr -d ".sh")
sub_logdir="$LOG_DIR/json_log"
debug_dir="$LOG_DIR/debug"
debug_file="$FILE.log"
JSN_DIR="json_file"
JSN_FIL="$FILE.json"
bannerfile="banner.txt"


                ###     DISPLAY FEATURES      ###
function banner()
{
        cat ${bannerfile}
}

                ###     WRITE FUNCTION    ###
function write_result()
{
        local level chp catg ids res
        level=$1
        chp=$2
        catid=$3
        ids=$4
        descr=$5
        res=$6
        echo "level:$level;chapter:$chp;categorie:$catid;rule:$ids;description:$descr;result:$res" >> $LOG_DIR/$FILE.log
}

function write_result2()
{
        local level chp catg ids res
        level=$1
        chp=$2
        catid=$3
        ids=$4
        res=$5

        #Retrieve result from json file
        oldval=$(jq -c --arg level ${level} --arg chp ${chp} --arg catid ${catid} --arg id ${ids} ".audit[] | select(.level==$level) | .chapters[\"$chp\"].categories[] | select(.id==$catid) | .report[] | select(.id==\"$id\")" "$JSN_DIR/$JSN_FIL")

        newval=$(jq --arg level ${level} --arg chp ${chp} --arg catid ${catid} --arg id ${ids} --arg result ${res} ".audit[] | select(.level==$level) | .chapters[\"$chp\"].categories[] | select(.id==$catid) | .report[] | select(.id==\"$id\") | .result=\"$result\"" "$JSN_DIR/$JSN_FIL")

        #Update the json_file with new value
        sed -i "s@${oldval}@${newval}@" "$JSN_DIR/$JSN_FIL"
}

function write_info()
{
        if [ verbose ]; then
                echo "$(date -Ins) [INFO] $@" | tee -a "$debug_dir/$debug_file"
        else
                echo "$(date -Ins) [INFO] $@" >> "$debug_dir/$debug_file"
        fi
}

function write_debug()
{
        if [ verbose ]; then
                echo "$(date -Ins) [DEBUG] $@" | tee -a "$debug_dir/$debug_file"
        else
                echo "$(date -Ins) [DEBUG] $@" >> "$debug_dir/$debug_file"
        fi
}

                ###     Renaming LOG FILE       ###
function rename()
{
        local TMP_DIR TMP_FILE
        TMP_DIR=$1
        TMP_FILE=$2

        #RENAME LOG FILE by adding timestamp to it
        NEW_FIL="${TMP_FILE}.$(date "+%Y%m%d_%H%M%S")"
        mv "${TMP_DIR}/${TMP_FILE}" "${TMP_DIR}/${NEW_FIL}"
        mv "${TMP_DIR}/${NEW_FIL}" "${sub_logdir}/${NEW_FIL}"
}

                ###       DEFINE FUNCTIONS      ###

## USAGE FUNCTION ##
function usage()
{
        cat << EOF
OPTIONS:
        -h,     --help          Display the help message
        -ls,    --list
        -l,     --level         Indicate the level 1 or 2 for server/workstation to audit
        -e,     --exclude       Indicate the level and categories id to be excluded from auditingi.
                                FORMAT: LEVEL.CAT_ID meaning level first followed by categories id
                                e.g. 1.1.1  ==> meaning exclude level 1 and categories id 1.1
        -vv,    --verbose       Display the debug file, while the script is running
        -sh,    --show          Display results from the json file

EXAMPLE:
        sudo $0 -e 1.1.1,2.1.1 -vv    #Execute the script to audit both LEVEL 1 & 2 but exclude categories id 1.1
        sudo $0 -l 1 -e 1.2.1,1.6.1 -vv
        sudo $0 -l 2 -e 2.1.1, 2.3.1 -vv

EOF
}

function display()
{
        cat << EOF
CentOS 8 Auditing Scripts
Level 1:
        Chapter 1:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  1.1            |  FILESYSTEM CONFIGURATION
                  -------------------------------------------
                  1.2            |  SOFTWARE UPDATES
                  -------------------------------------------
                  1.3            |  SUDO
                  -------------------------------------------
                  1.4            |  FILESYSTEM INTEGRITY
                                 |  CHECK
                  -------------------------------------------
                  1.5            |  SECURE BOOT SETTINGS
                  -------------------------------------------
                  1.6            |  ADDITIONAL PROCESS
                                 |  HARDENING
                  -------------------------------------------
                  1.7            |  WARNING BANNERS
                  -------------------------------------------

        Chapter 2:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  2.1            |  INETD SERVICE
                  -------------------------------------------
                  2.2            |  TIME SYNCHRONIZATION
                  -------------------------------------------
                  2.3            |  SPECIAL PURPOSE SERVICES
                  -------------------------------------------
                  2.4            |  SERVICE CLIENTS
                  -------------------------------------------

        Chapter 3:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  3.1            |  NETWORK PARAMETER (host only)
                  -------------------------------------------
                  3.2            |  NETWORK PARAMETER (host and router)
                  -------------------------------------------
                  3.3            |  FIREWALL CONFIGURATION
                  -------------------------------------------
                  3.4            |  WIRELESS INTERFACES
                  -------------------------------------------

        Chapter 4:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  4.1            |  CONFIGURE LOGGING
                  -------------------------------------------
                  4.2            |  LOG ROTATION
                  -------------------------------------------

        Chapter 5:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  5.1            |  CONFIGURE CRON
                  -------------------------------------------
                  5.2            |  SSH SERVER CONFIGURATION
                  -------------------------------------------
                  5.3            |  CONFIGURE AUTHSELECT
                  -------------------------------------------
                  5.4            |  CONFIGURE PAM
                  -------------------------------------------
                  5.5            |  USER ACCOUNTS &
                                 |  Environment
                  -------------------------------------------
                  5.6            |  ROOT LOGIN CONFIGURATION
                  -------------------------------------------
                  5.7            |  SU COMMAND
                  -------------------------------------------

        Chapter 6:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  6.1            |  SYSTEM FILE PERMISSIONS
                  -------------------------------------------
                  6.2            |  USER & GROUP SETTINGS
                  -------------------------------------------


Level 2:
        Chapter 1:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  1.1            |  FILESYSTEM CONFIGURATION
                  -------------------------------------------
                  1.2            |  MANDATORY ACCESS CONTROL
                  -------------------------------------------
                  1.3            |  WARNING BANNERS
                  -------------------------------------------

        Chapter 3:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  3.1            |  UNCOMMON NETWORK PROTOCOL
                  -------------------------------------------
                  3.2            |  WIRELESS CONFIGURATION
                  -------------------------------------------
                  3.3            |  DISABLE IPv6
                  -------------------------------------------

        Chapter 4:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  4.1            |  CONFIGURE SYSTEM
                                 |  ACCOUNTING
                  -------------------------------------------

        Chapter 5:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  5.1            |  SSH SERVER CONFIGURATION
                  -------------------------------------------

        Chapter 6:
        ||
        ========> Categories ID  |      Name
                  -------------------------------------------
                  6.1            |  SYSTEM FILE PERMISSIONS
                  -------------------------------------------

EOF
}

function run_test()
{
        local args level funct id descr
        args=$("$@")
        funct=$1
        level=$2
        shift
        shift
        id=$3
        descr="$4"

        write_debug "Level $level, $descr ($id), function used : $funct"
}

function test_excluded()
{
        local excl num
        excl=$1
        num=0
        ex_test=($(echo "$excl" | sed 's/,/ /g'))

        while [ -n "${ex_test[num]}" ]; do
                if [ "$(echo "${ex_test[num]}" | awk -F . '{if($1 == 1) print 0}')" == "0" ]; then
                        var=$(echo "${ex_test[num]}" | sed 's/^[[:digit:]]\.//g')
                        excl_arr1+=("${var}")
                elif [ "$(echo "${ex_test[num]}" | awk -F . '{if($1 == 2) print 0}')" == "0" ]; then
                        var=$(echo "${ex_test[num]}" | sed 's/^[[:digit:]]\.//g')
                        excl_arr2+=("${var}")
                else
                        echo "Invalid format or value being passed"
                fi
                num=$((num + 1))
        done
}
                ###  Display result in table format  ###
function retrieve()
{
        local description formatter pass fail na level all
        pass=0
        fail=0
        na=0
        description=""
        formatter=""
        level=$1
        all=$2

        #create textfile
        touch "$JSN_DIR/retrieve.txt"

        l1Array=("one" "two" "three" "four" "five" "six")
        l2Array=("one" "three" "four" "five" "six")

        if [[ $level -eq 1 ]] || [[ $all -eq 1 ]]; then
                echo "LEVEL 1"
                for chp in "${l1Array[@]}"; do
                        echo "========="
                        echo "Chp $chp"
                        echo "========="
                        catidArr1=($(jq -c --arg chp ${chp} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | .id" "$JSN_DIR/$JSN_FIL"))
                        for cid in "${catidArr1[@]}"; do
                                pass=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Pass" | wc -l)
                                fail=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Fail" | wc -l)
                                na=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Null" | wc -l)
                                description=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==1) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .name" "$JSN_DIR/$JSN_FIL")
                                description=$(echo "${description}" | sed -e "s/\"//g")
                                echo "$cid,$description,$pass,$fail,$na,$total" >> "$JSN_DIR/retrieve.txt"
                        done
                        (
                                echo -e "\t--,-----------,----,----,----"
                                echo -e "\tID,Description,Pass,Fail,Null"
                                echo -e "\t--,-----------,----,----,----"
                                while read line; do
                                        echo -e "\t$line"
                                done < "$JSN_DIR/retrieve.txt"
                        ) | column -t -s ","
                done
        fi

        echo " "
        echo " "

        if [[ $level -eq 2 ]] || [[ $all -eq 1 ]]; then
                echo "LEVEL 2"
                for chp in "${l2Array[@]}"; do
                        echo "========="
                        echo "Chp $chp"
                        echo "========="
                        catidArr2=($(jq -c --arg chp ${chp} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | .id" "$JSN_DIR/$JSN_FIL"))
                        for cid in "${catidArr2[@]}"; do
                                pass=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Pass" | wc -l)
                                fail=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Fail" | wc -l)
                                na=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .report[]" "$JSN_DIR/$JSN_FIL" | grep "Null" | wc -l)
                                description=$(jq -c --arg chp ${chp} --arg cid ${cid} ".audit[] | select(.level==2) | .chapters[\"$chp\"].categories[] | select(.id==$cid) | .name" "$JSN_DIR/$JSN_FIL")
                                description=$(echo "${description}" | sed -e "s/\"//g")
                                echo "$cid,$description,$pass,$fail,$na,$total" >> "$JSN_DIR/retrieve.txt"
                        done
                        (
                                echo -e "\t--,-----------,----,----,----"
                                echo -e "\tID,Description,Pass,Fail,Null"
                                echo -e "\t--,-----------,----,----,----"
                                while read line; do
                                        echo -e "\t$line"
                                done < "$JSN_DIR/retrieve.txt"
                        ) | column -t -s ","
                done
        fi

        rm "$JSN_DIR/retrieve.txt"
}


                ###   COMMON FUNCTION FOR BOTH LVL 1 & 2, ACROSS ALL CHAPTERS   ###
function not_scored()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        result="Null"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function chkpkg_installed()
{
        #verify if the package is installed/not installed
        local id pkge isinstall
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        pkgs=$6
        isinstall=$7
        score=0

        #description: Ensure pkges is/are installed/not installed

        #= TEST =#
        list=(${pkgs//,/ })
        pkg_nbr=$(echo ${list[@]} | wc -w)
        for pkge in $(echo ${list[@]}) ; do
                if [[ "$isinstall" -eq 1 ]] ; then
                        [ $(rpm -qa $pkge | wc -l) -eq 1 ] && score=$((score+1))
                elif [[ "$isinstall" -eq 0 ]] ; then
                        [ $(rpm -qa $pkge | wc -l) -eq 0 ] && score=$((score+1))
                fi
        done
        [ $score -eq $pkg_nbr ] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function is_enabled()
{
        local id service
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        service=$6
        score=0

        #= TEST =#
        [ $(systemctl is-enabled $service 2>/dev/null | grep enabled | wc -l) -ne 0 ] && score=$((score+1))
        [ $(systemctl is-active $service 2>/dev/null | grep enabled | wc -l) -ne 0 ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function is_disabled()
{
        ## Local Variables ##
        local id score var
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6
        score=0

        #description="Ensure $var kernel module is not available"

        #= TEST =#
        [[ "$(modprobe -n -v $var 2> /dev/null | tail -1)" =~ "install /bin/true" ]] && score=$((score+1))
        [ $(lsmod | grep $var | wc -l) -eq 0 ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        #Append the result to LOG_FILE
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}



                ###---------- LEVEL 1 ----------###
                ## -- CHAPTER ONE --##
## -- FILESYSTEM FUNCTION -- ##
#Ensure /tmp is configured
function tmp_config()
{
        ## Local Variables ##
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description="Ensure /tmp is configured"

        #= TEST =#
        [ $(findmnt -kn /tmp | wc -l) -eq 1 ] && score=$((score+1))
        [ $(systemctl is-enabled tmp.mount 2> /dev/null | grep -E 'disabled' |wc -l) -ne 0 ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

#Check for nodev
function check_fs_nodev()
{
        ## Local Variables ##
        local id partition isScored score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        partition=$6
        isScored=$7
        score=0

        #description="Ensure nodev option set on $partition partition"

        #= TEST =#
        #check for nodev
        [ $(findmnt -kn $partition | grep -v nodev | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

#Check for nosuid
function check_fs_nosuid()
{
        ## Local Variables ##
        local id partition isScored score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        partition=$6
        isScored=$7
        score=0

        #description="Ensure nosuid option set on $partition partition"

        #= TEST =#
        #check for nosuid
        [ $(findmnt -kn $partition | grep -v nosuid | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

#Check for noexec
function check_fs_noexec()
{
        ## Local Variables ##
        local id partition isScored score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        partition=$6
        isScored=$7
        score=0

        #description="Ensure noexec option set on $partition partition"

        #= TEST =#
        #check for noexec
        [ $(findmnt -kn $partition | grep -v noexec | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

#Ensure Sticky bit is set on all world-writable directories
function sticky_bit()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description="Ensure sticky bit is set on all world-writable directories"

        #= TEST =#
        [ $(df --local -P | awk '{if (NR!=1) print$6}'| xargs -l '{}' find '{}' -xdev -type d \( -perm -002 -a ! -perm -1000 \) 2> /dev/null | wc -l) -eq 0 ] && result="Pass"

        #Append result to LOG_FILE
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

#Disable Automounting
function disable_automount()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description="Disable Automounting"

        #= TEST =#
        [ $(systemctl is-enabled autofs 2> /dev/null | grep -E 'disabled' | wc -l) -ne 0 ] && result="Null"

        #Append result to LOG_FILE
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}


##-- SOFTWARE UPDATE --##
function gpg_check()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure gpgcheck is globally activated

        #= TEST =#
        [ $(grep ^gpgcheck=1 /etc/dnf/dnf.conf | wc -l) -ne 0 ] && score=$((score+1))
        [ $(grep ^gpgcheck=1 /etc/yum.repos.d/* | wc -l) -eq $(grep ^gpgcheck /etc/yum.repos.d/* | wc -l) ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function repo_gpg_check()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure gpgcheck is globally activated

        #= TEST =#
        [ $(grep ^repo_gpgcheck=1 /etc/dnf/dnf.conf | wc -l) -ne 0 ] && score=$((score+1))
        [ $(grep ^repo_gpgcheck=1 /etc/yum.repos.d/* | wc -l) -eq $(grep ^repo_gpgcheck /etc/yum.repos.d/* | wc -l) ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}


##-- SUDO --##
function sudo_pty()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure sudo commands use pty

        #= TEST =#
        [ $(grep -rPi '^\h*Defaults\h+([^#\n\r]+,)?use_pty(,\h*\h+\h*)*\h*(#.*)?$' /etc/sudoers* 2> /dev/null | wc -l) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function sudo_log()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure sudo log file exists

        #= TEST =#
        [ $(grep -rPsi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" /etc/sudoers* 2> /dev/null | wc -l) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function sudoers_cfg()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6

        #description: Ensure sudo log file exists

        #= TEST =#
        [ $(grep -r "$var" /etc/sudoers* 2> /dev/null | wc -l) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

##-- FILESYSTEM INTEGRITY CHECKING --##
function fs_periodic_check()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure filesystem integrity is regularly checked

        #= TEST =#
        [[ "$(systemctl is-enabled aidecheck.service 2> /dev/null)" =~ "enabled" ]] && score=$((score+1))
        [[ "$(systemctl is-enabled aidecheck.timer 2> /dev/null)" =~ "enabled" ]] && score=$((score+1))
        [[ "$(systemctl status aidecheck.timer 2> /dev/null)" =~ "active" ]] && score=$((score+1))
        [ $score -eq 3 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function aide_conf()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [[ $(grep -Ps -- '(\/sbin\/(audit|au)\H*\b)' /etc/aide.conf.d/*.conf /etc/aide.conf | wc -l) -eq 6  ]] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

##-- Secure Boot Settings --##
function boot_config()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure permissions on bootloader config are configured

        #= TEST =#
        [ $(stat /boot/grub2/grub.cfg /boot/grub2/grubenv | grep 0600 | wc -l) -eq 2 ] && score=$((score+1))
        [ $(stat /boot/grub2/grub.cfg /boot/grub2/grubenv | egrep -o "0\/\s+root" | wc -l) -eq 4 ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function boot_passwd()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure bootloader password is set

        #= TEST =#
        [ $(grep "^\s*GRUB2_PASSWORD" /boot/grub2/user.cfg 2> /dev/null | wc -l) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function auth_single_usr()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure authentication required for single user mode

        #= TEST =#
        [ $(grep /systemd-sulogin-shell /usr/lib/systemd/system/rescue.service /usr/lib/systemd/system/emergency.service 2> /dev/null | wc -l) -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}


##-- Additional Process Hardening --##
function cd_restrict()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure core dumps are restricted

        #= TEST =#
        [ $(grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf /etc/security/limits.d/* 2> /dev/null | wc -l) -ne 0 ] && score=$((score+1))
        [ $(sysctl fs.suid_dumpable | wc -l) -ne 0 ] && score=$((score+1))
        [ $(grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | wc -l) -ne 0 ] && score=$((score+1))
        [ $(systemctl is-enabled coredump.service 2> /dev/null | wc -l) -ne 0 ] && score=$((score+1))
        [ $score -eq 4 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function cd_backtraces_disabled()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure core dump backtraces are disabled

        #= TEST =#
        [ $(grep "^ProcessSizeMax=0" /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/* 2> /dev/null | wc -l ) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function cd_storage_disabled()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure core dump cwstorage is disabled

        #= TEST =#
        [ $(grep "^Storage=none" /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/* 2> /dev/null | wc -l ) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function alsr_enabled()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description; Ensure address space layout randomization (ALSR) is enabled

        #= TEST =#
        [ $(sysctl kernel.randomize_va_space | grep 2 | wc -l) -ne 0 ] && score=$((score+1))
        [ $(grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | wc -l ) -ne 0 ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function ptrace_restricted()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description; Ensure ptrace_scope is restricted

        #= TEST =#
        [ $(sysctl kernel.yama.ptrace_scope | grep 1 | wc -l) -ne 0 ] && score=$((score+1))
        [ $(grep "kernel\.yama\.ptrace_scope" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | wc -l ) -ne 0 ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}


##-- Message of the Day --##
function motd_contens()
{
        local id motd score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        motd=$6

        #description: Ensure messages|local login warning banner|remote login warning banner & permissions are configured properly
        #files: /etc/motd , /etc/issue , /etc/issue.net

        #= TEST =#
        [[ $(grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" "$motd" | wc -l) -eq 0 ]] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function motd_config()
{
        local id motd score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        motd=$6
        score=0

        #description: Ensure messages|local login warning banner|remote login warning banner & permissions are configured properly
        #files: /etc/motd , /etc/issue , /etc/issue.net

        #= TEST =#
        [ $(stat $motd | grep 0644 | wc -l) -ne 0 ] && score=$((score+1))
        [ $(stat $motd | egrep -o "0\/\s+root" | wc -l) -eq 2 ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function gdm_config()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure GDM login banner is configured

        #= TEST =#
        gdm_file="/etc/dconf/profile/gdm"
        banner_file="/etc/dconf/db/gdm.d/01-banner-message"

        if [[ "$(rpm -q gdm)" != "package gdm is not installed" ]] ; then
                if [ -f $gdm_file ] ; then
                        if [ -f $banner_file ] ; then
                                [ $(egrep "^banner-message-enable=true" $banner_file | wc -l) -eq 1 ] && score=$((score+1))
                                [ $(egrep "banner-message-text=.*" $banner_file | wc -l) -eq 1 ] && score=$((score+1))
                                [ $score -eq 2 ] && result="Pass"
                        fi
                fi
        else
                result="Pass"
        fi
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function crypto_policy()
{
        local id legacy
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        legacy=$6

        #description: Ensure system-wide crypto policy is not legacy
        #description: Ensure system-wide crypto policy is FUTURE or FIPS

        #= TEST =#
        if [ $legacy -eq 1 ]
        then
                [ $(grep -E -i '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config | wc -l) -eq 0 ] && result="Pass"
        else
                [ $(grep -E -i '^\s*(FUTURE|FIPS)\s*(\s+#.*)?$' /etc/crypto-policies/config | wc -l) -ne 0 ] && result="Pass"
        fi

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function crypto_disabled_sha1()
{
        local id legacy
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure system wide crypto policy disables sha1 hash and signature support

        #= TEST =#
        [ $(grep -Pi -- '^\h*(hash|sign)\h*=\h*([^\n\r#]+)?-sha1\b' /etc/crypto-policies/state/CURRENT.pol | wc -l) -eq 0 ] && score=$((score+1))
        [[ "$(grep -Pi -- '^\h*sha1_in_certs\h*=\h*' /etc/crypto-policies/state/CURRENT.pol)" =~ "sha1_in_certs = 0" ]] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function crypto_disabled_cbc()
{
        local id legacy
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure system wide crypto policy disables cbc for ssh

        #= TEST =#
        [ $(grep -Piq -- '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*' /etc/crypto-policies/state/CURRENT.pol | wc -l) -eq 0 ] && score=$((score+1))
        [ $(grep -Piq -- '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol | wc -l) -eq 0 ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function crypto_macs()
{
        local id legacy
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure system wide crypto policy disables macs less than 128 bits

        #= TEST =#
        [ $(grep -Pi -- '^\h*mac\h*=\h*([^#\n\r]+)?-64\b' /etc/crypto-policies/state/CURRENT.pol | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

                ## -- CHAPTER TWO -- ##
function chrony_config()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure chrony is configured

        #= TEST =#
        [ $(grep -Prs -- '^\h*(server|pool)\h+[^#\n\r]+' /etc/chrony.conf /etc/chrony.d/ | wc -l) -ne 0 ] && score=$((score+1))
        [ $(ps -ef | grep chronyd &> /dev/null; echo $?) -eq 0 ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function chrony_none_root()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure chrony is not run as the root user

        #= TEST =#
        [ $(grep -Psi -- '^\h*OPTIONS=\"?\h+-u\h+root\b' /etc/sysconfig/chronyd | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function not_enabled()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        serv=$6

        #description: Ensure these services are not enabled

        #= TEST =#
        [ $(systemctl is-enabled $serv 2> /dev/null | grep disabled | wc -l) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function mail_tagent()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure mail transfer agent is configured

        #= TEST =#
        [ $(ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s' &> /dev/null; echo $?) -eq 0 ] && result="Pass"

         write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

                ## -- CHAPTER THREE -- ##
##--Network Parameter (Host Only) && (Host and Router)--##
function sysctl_1()
{
        local id protocol query ipv6 query6 score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        query=$6
        value=$7
        ipv6=$8
        query6=$9
        score=0

        #= TEST =#
        if [ $ipv6 -eq 1 ] #Check if ipv6 is needed for the Test
        then
                [ $(sysctl net.ipv4.$query | awk '{print $3}') -eq $value ] && score=$((score+1))
                [ $(grep -E -s "^\s*net\.ipv4\.$query\s*=\s*$value" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | wc -l) -eq 1 ] && score=$((score+1))

                [ $(sysctl net.ipv6.conf.all.$query6 | awk '{print $3}') -eq $value ] && score=$((score+1))
                [ $(grep -E -s "^\s*net\.ipv6\.conf\.all\.$query6\s*=\s*$value" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | wc -l) -eq 1 ] && score=$((score+1))

                [ $score -eq 4 ] && result="Pass"
        else
                [ $(sysctl net.ipv4.$query | awk '{print $3}') -eq $value ] && score=$((score+1))
                [ $(grep -E -s "^\s*net\.ipv4\.$query\s*=\s*$value" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | wc -l) -eq 1 ] && score=$((score+1))

                [ $score -eq 2 ] && result="Pass"
        fi

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function sysctl_2()
{
        local id protocol query ipv6 score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        query=$6
        value=$7
        ipv6=$8
        score=0

        #= Test =#
        if [ $ipv6 -eq 1 ]
        then
                #IPv4
                [ $(sysctl net.ipv4.conf.all.$query 2> /dev/null | awk '{print $3}') -eq $value ] || score=$((score+1))
                [ $(grep "net\.ipv4\.conf\.all\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(sysctl net.ipv4.conf.default.$query 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(grep "net\.ipv4\.conf\.default\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))

                #IPv6
                [ $(sysctl net.ipv6.conf.all.$query 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(grep "net\.ipv6\.conf\.all\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(sysctl net.ipv6.conf.default.$query 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(grep "net\.ipv6\.conf\.default\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))


        else
                [ $(sysctl net.ipv4.conf.all.$query 2> /dev/null | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
                [ $(grep "net\.ipv4\.conf\.all\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(sysctl net.ipv4.conf.default.$query 2> /dev/null| grep 0 | wc -l) -ne 0 ] && score=$((score+1))
                [ $(grep "net\.ipv4\.conf\.default\.$query" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null | grep 0 | wc -l) -ne 0 ] || score=$((score+1))

        fi

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function ipv6_route()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        [ $(sysctl net.ipv6.conf.all.accept_ra 2> /dev/null | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
        [ $(grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
        [ $(sysctl net.ipv6.conf.default.accept_ra 2> /dev/null | grep 0 | wc -l) -ne 0 ] && score=$((score+1))
        [ $(grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* | grep 0 | wc -l) -ne 0 ] && score=$((score+1))

        [ $score -eq 4 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

##--Firewall Configuration--##
function fw_isinstall()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure firewalld, nftables & iptables are installed

        #= TEST =#
        [ $(rpm -q firewalld &> /dev/null;echo $?) -eq 0 ] && [ $(rpm -q nftables &> /dev/null;echo $?) -eq 0 ] && [ $(rpm -q iptables &> /dev/null;echo $?) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fw_chkenabled()
{
        local id serv
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        serv=$6
        score=0

        #description: Check if firewalld is enabled & running; Check if nftables & iptables are disabled and inactive

        #= TEST =#
        [ $(systemctl is-enabled firewalld | grep enabled | wc -l) -ne 0 ] && [ $(systemctl is-active firewalld | grep active | wc -l) -ne 0 ] && score=$((score+1))
        [ $(systemctl is-enabled nftables 2> /dev/null | grep disabled | wc -l) -ne 0 ] && [ $(systemctl is-active nftables 2>/dev/null | grep inactive | wc -l) -ne 0 ] && score=$((score+1))
        [ $(systemctl is-enabled iptables 2> /dev/null | grep disabled | wc -l) -ne 0 ] && [ $(systemctl is-active iptables 2>/dev/null | grep inactive | wc -l) -ne 0 ] && score=$((score+1))
        [[ $(rpm -q iptables | wc -l) -eq 0 ]] && score=$((score+1))
        [ $score -eq 4 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function default_zone()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure default zone is set

        #= TEST =#
        [ $(firewall-cmd --get-default-zone &> /dev/null;echo $?) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function nft_1()
{
        local id var
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6

        #= TEST =#
        [ $(nft list $var | wc -l) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function nft_2()
{
        local id score policy
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        policy=$6
        score=0

        #= TEST =#
        if [[ "$policy" == "drop" ]] ; then
                [ $(nft list ruleset | grep 'hook input' | grep drop | wc -l) -ne 0 ] && score=$((score+1))
                [ $(nft list ruleset | grep 'hook forward' | grep drop | wc -l) -ne 0 ] && score=$((score+1))
                [ $score -eq 2 ] && result="Pass"
        else
                [ $(nft list ruleset | grep 'hook input' | wc -l) -ne 0 ] && score=$((score+1))
                [ $(nft list ruleset | grep 'hook forward' | wc -l) -ne 0 ] && score=$((score+1))
                [ $(nft list ruleset | grep 'hook output' | wc -l) -ne 0 ] && score=$((score+1))
                [ $score -eq 3 ] && result="Pass"
        fi

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function nft_3()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        [ $(nft list ruleset | awk '/hook\s+input\s+/,/\}\s*(#.*)?$/' | grep -Pq -- '\H+\h+"lo"\h+accept' ; echo $?) -eq 0 ] && score=$((score+1))
        [ $(nft list ruleset | awk '/filter_IN_public_deny|hook\s+input\s+/,/\}\s*(#.*)?$/' | grep -P -- 'ip\h+saddr' ; echo $?) -ne 1 ] && score=$((score+1))
        [ $(nft list ruleset | awk '/filter_IN_public_deny|hook input/,/}/' | grep 'ip6 saddr' ; echo $?) -ne 1 ] && score=$((score+1))

        [ $score -eq 3 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function chk_iptables()
{
        local id score var protocol
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6
        score=0

        if [ "$var" == "loopback" ]
        then
                [ $(iptables -L INPUT -v -n | grep lo | wc -l) -ne 0 ] && [ $(iptables -L INPUT -v -n | grep 127 | wc -l) -ne 0 ] || score=$((score+1))
                [ $(iptables -L OUTPUT -v -n | grep lo | wc -l) -ne 0 ] || score=$((score+1))
        else
                [ $(iptables -L | grep -E 'INPUT (policy DROP)') ] || score=$((score+1))
                [ $(iptables -L | grep -E 'FORWARD (policy DROP)') ] || score=$((score+1))
                [ $(iptables -L | grep -E 'OUTPUT (policy DROP)') ] || score=$((score+1))
        fi

        [ $score -eq 0 ] && result="Pass"

         write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function nftrul_perm()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        #INPUT
        [ $([[ -n $(grep -E "^\s*include" /etc/sysconfig/nftables.conf) ]] && awk '/hook input/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf); echo $?) -ne 1 ] && score=$((score+1))

        #FORWARD
        [ $([[ -n $(grep -E "^\s*include" /etc/sysconfig/nftables.conf) ]] && awk '/hook forward/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf);echo $?) -ne 1 ] && score=$((score+1))

        #OUTPUT
        [ $([[ -n $(grep -E "^\s*include" /etc/sysconfig/nftables.conf) ]] && awk '/hook output/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf);echo $?) -ne 1 ] && score=$((score+1))

        [ $score -eq 3 ] && result="Pass"

         write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fwll_op()
{
        local id score var arr
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure firewall rules exist for all open ports

        #= TEST =#
        var=$(ss -4tuln | awk  '{print $5}' | awk -F ':' '{print $2}' | awk NR\>1)
        arr=($var)
        total=${#arr[@]}

        for i in "${var[@]}"
        do
                [ $(iptables -L INPUT -v -n | grep ":$i" | grep ACCEPT &> /dev/null; echo $?) -ne 1 ] && score=$((score+1))
        done

        [ $score -eq $total ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function chk_ip6tables()
{
        local id score var
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6

        #description: Ensure IPv6 loopback traffic is configured

        #= TEST =#
        if [ "$var" == "loopback" ]
        then
                [ $(ip6tables -L INPUT -v -n | grep lo | grep ACCEPT | wc -l) -ne 0 ] || score=$((score+1))
                [ $(ip6tables -L INPUT -v -n | grep ::1 | grep DROP | wc -l) -ne 0 ] || score=$((score+1))
                [ $(ip6tables -L OUTPUT -v -n | grep lo | grep ACCEPT | wc -l) -ne 0 ] || score=$((score+1))
        else
                [ $(ip6tables -L | grep -E 'INPUT (policy DROP)') ] || score=$((score+1))
                [ $(ip6tables -L | grep -E 'FORWARD (policy DROP)') ] || score=$((score+1))
                [ $(ip6tables -L | grep -E 'OUTPUT (policy DROP)') ] || score=$((score+1))
        fi

        [[ $score -eq 0 ]] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function wifi_config()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        [ $(find /sys/class/net/*/ -type d -name wireless | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}


                ## -- CHAPTER FOUR -- ##
##-- CONFIGURE LOGGING --##
function rsyslog_perm()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure rsyslog default file permissions configured

        #= TEST =#
        [ $(grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null | grep -E '(0640||0600)' | wc -l) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function rsyslog_client()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure rsyslog is configured to send logs to a remote log host (Scored)

        #= TEST =#
        [ $(grep -Ps -- '^\h*module\(load="imtcp"\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf ; echo $?) -eq 1 ] && score=$((score+1))
        [ $(grep -Ps -- '^\h*input\(type="imtcp" port="514"\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf ; echo $?) -eq 1 ] && score=$((score+1))
        [ $(grep -s '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf ; echo $?) -eq 1 ] && score=$((score+1))
        [ $(grep -s '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf ; echo $?) -eq 1 ] && score=$((score+1))

        [[ $score -eq 4 ]] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function send_log()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure rsyslog is configured to send logs to a remote log host (Scored)

        #= TEST =#
        [ $(grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null | wc -l) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function journald_cfg()
{
        local id query
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #function created for id 4.1.6/.7/.8

        #= TEST =#
        if [[ "$id" == "5.1.1.3" ]] ; then
                [ $(grep -e ^\s*ForwardToSyslog /etc/systemd/journald.conf 2> /dev/null | wc -l) -ne 0 ] && result="Pass"
        elif [[ "$id" == "5.1.2.3" ]] ; then
                [ $(grep -e ^\s*Compress /etc/systemd/journald.conf 2> /dev/null | wc -l) -ne 0 ] && result="Pass"
        elif [[ "$id" == "5.1.2.4" ]] ; then
                [ $(grep -e ^\s*Storage /etc/systemd/journald.conf 2> /dev/null | wc -l) -ne 0 ] && result="Pass"
        fi

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function permlog_cfg()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure permissions on all logfiles are configured

        #= TEST =#
        [ $(find /var/log -type f -perm /037 -ls -o -type d -perm /026 -ls 2> /dev/null | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

                ## -- CHAPTER FIVE -- ##
##-- CONFIGURE CRON --##
function cron_perm()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        file=$6
        score=0

        #= TEST =#
        [ $(stat /etc/$file.allow &> /dev/null; echo $?) -eq 0 ] && score=$((score+1))
        [ $(stat /etc/$file.allow 2> /dev/null | egrep "^Access:\s+\S+(0600|0640)\/\S+" | wc -l) -eq 1 ] && score=$((score+1))
        [ $(stat /etc/$file.allow 2> /dev/null | egrep -o "0\/\s+root" | wc -l) -eq 1 ] && score=$((score+1))
        if [ $(stat /etc/$file.deny &> /dev/null; echo $?) -eq 0 ] ; then
                [ $(stat /etc/$file.deny &> /dev/null; echo $?) -eq 0 ] && score=$((score+1))
                [ $(stat /etc/$file.deny 2> /dev/null | egrep "^Access:\s+\S+(0600|0640)\/\S+" | wc -l) -eq 1 ] && score=$((score+1))
                [ $(stat /etc/$file.deny 2> /dev/null | egrep -o "0\/\s+root" | wc -l) -eq 1 ] && score=$((score+1))
                [ $score -eq 6 ] && result="Pass"
        else
                [ $score -eq 3 ] && result="Pass"
        fi

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}


##-- SSH SERVER CONFIGURATION --##
function ssh_key_config()
{
        local id score pub total
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        pub=$6
        score=0

        #= TEST =#
        if [[ "$pub" -ne 1 ]] ; then
                total=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | egrep -o "File:\s+\S+" | wc -l)
                [ $(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | egrep "^Access:\s+\S+0600\/\S+" | wc -l) -eq $total ] || score=$((score+1))
                [ $(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | egrep "0\/\s+root" | wc -l) -eq ${total} ] || score=$((score+1))

        else
                total=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | egrep -o "File:\s+\S+" | wc -l)
                [ $(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | egrep "^Access:\s+\S+(0600|0700)\/\S+" | wc -l) -eq $total ] || score=$((score+1))
                [ $(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | egrep "0\/\s+root" | wc -l) -eq ${total} ] || score=$((score+1))
        fi

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function ssh_cfg_1()
{
        local id var query double
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6
        query=$7


        #= TEST =#
        [ $(sshd -T | grep ${var} | egrep "${query}" | wc -l) -ne 0 ] && result="Pass"


        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function ssh_cfg_2()
{
        local id score var1 var2 query1 query2
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var1=$6
        var2=$7
        query1=$8
        query2=$9
        score=0

        #= TEST =#
        [ $(sshd -T | grep ${var1} | egrep "${query1}" | wc -l) -ne 0 ] || score=$((score+1))
        [ $(sshd -T | grep ${var2} | egrep "${query2}" | wc -l) -ne 0 ] || score=$((score+1))

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function ssh_cfg_access()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(sshd -T | grep -E "^\s*(allow|deny)(users|groups)\s+\S+()" | wc -l) -eq 4 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function ssh_cypher()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep ciphers | egrep -v '3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|rijndael-cbc@lysator.liu.se|aes128-ctr' | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function ssh_kexalgo()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep kexalgorithms | egrep -v 'diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1' | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function ssh_macs()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep macs | egrep -v 'hmac-md5 hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh.com|hmac-md5-etm@openssh.com|hmac-md5-96-etm@openssh.com|hmac-ripemd160-etm@openssh.com|hmac-sha1-96-etm@openssh.com|umac-64-etm@openssh.com' | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function ssh_crypto()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(grep '^/s*CRYPTO_POLICY=' /etc/sysconfig/sshd | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

## -- CONFIGURE AUTHSELECT -- ##
function auth_custom()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        [ $(authselect current | grep "Profile ID:" | wc -l) -ne 0 ] || score=$((score+1))
        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function auth_profile()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        [ $(authselect current | egrep "sudo|faillock|nullok" | wc -l) -eq 3 ] || score=$((score+1))
        [ $score -eq 0 ] && resul="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function auth_flck()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        [ $(authselect current | grep with-faillock | wc -l) -ne 0 ] || score=$((score+1))
        [ $(grep with-faillock /etc/authselect/authselect.conf | wc -l) -ne 0 ] || score=$((score+1))

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

##-- CONFIGURE PAM --##
function pam_config()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6
        score=0

        #= TEST =#
        [ $(grep -P -- '\b$var\b' /etc/pam.d/{password,system}-auth | wc -l) -ne 0 ] && result="Pass"

         write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

##-- User Accounts and Environment (UAE) --##
function uae_cfg ()
{
        local id var val cut
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6
        val=$7
        cut=$8

        #= CHECKING FOR PASSWD_REVIEW_LIST =#
        if [[ -d "${LOG_DIR}/pwd_review_list" ]] ; then
                if [[ -f usr_list ]] ; then
                        write_info "usr_list exist under ${LOG_DIR}/pwd_review_list"
                else
                        touch "${LOG_DIR}/pwd_review_list/usr_list"
                fi
        else
                mkdir "${LOG_DIR}/pwd_review_list"
                touch "${LOG_DIR}/pwd_review_list/usr_list"
                write_info "Directory ${LOG_DIR}/pwd_review_list created"
                write_info "${LOG_DIR}/pwd_review_list/usr_list file created"
        fi

        #= TEST =#
        if [[ "$id" == "4.5.1.4" ]] ; then
                [[ $(useradd -D | grep "^${var}" | cut -f2 -d = ) -eq $val ]] && result="Pass"
        else
                [[ $(grep "^${var}" /etc/login.defs | cut -f2 ) -eq $val ]] && result="Pass"
        fi

        #= REVIEW LIST OF USERS that does not conforms the policy =#
        echo "$(date -Ins)"
        echo "Users whose account ${var}'s value is less than ${val}...." >> "${LOG_DIR}/pwd_review_list/usr_list"
        awk -F ":" -e '/^[^:]+:[^\!*]/ && $4 != '${val}' {print $1,$4}' /etc/shadow >> "${LOG_DIR}/pwd_review_list/usr_list"
        echo "=======================================================================================" >>  "${LOG_DIR}/pwd_review_list/usr_list"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function pwd_cfg()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        for user in $(cut -d: -f1 /etc/shadow); do
                last_date=$(chage --list $user | grep "^Last password change" | cut -d: -f2)

                if [[ "$last_date" != " never" ]]; then
                        [[ "$(date -d "$chge_date" +%s)" -lt "$(date +%s)" ]] || score=$((score+1))
                fi
        done

        [ $score -eq 0 ] && result="Pass"


        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function strong_pwd()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        [[ $(grep -qPi -- '^\h*crypt_style\h*=\h*(sha512|yescrypt)\b' /etc/libuser.conf ; echo $?) -eq 0 ]] && score=$((score+1))
        [[ $(grep -qPi -- '^\h*ENCRYPT_METHOD\h+(SHA512|yescrypt)\b' /etc/login.defs ; echo $?) -eq 0 ]] && score=$((score+1))

        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function sysacc_secured()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        [ $(awk -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' || $3 == 65534) && $7!~/^(\/usr)?\/sbin\/nologin$/) { print $1 }' /etc/passwd| wc -l) -eq 0 ] && score=$((score+1))
        [ $(awk -F: '/nologin/ {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' | wc -l) -eq 0 ] && score=$((score+1))

        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function def_usr_tmout()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        [[ $(grep -Pq '^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' /etc/bashrc /etc/profile /etc/profile.d/*.sh ; echo $?) -eq 0 ]] && score=$((score+1))
        [[ $(grep -Pq '^\s*([^#]+;\s*)?readonly\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' /etc/bashrc /etc/profile /etc/profile.d/*.sh ; echo $?) -eq 0 ]] &&score=$((score+1))
        [[ $(grep -Pq '^\s*([^#]+;\s*)?export\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' /etc/bashrc /etc/profile /etc/profile.d/*.sh ; echo $?) -eq 0 ]] &&score=$((score+1))
        [[ $(grep -Pq '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh /etc/bashrc ; echo $?) -eq 1 ]] &&score=$((score+1))

        [ $score -eq 4 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function def_grp_access()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(grep "^root:" /etc/passwd | cut -f4 -d:) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function def_usr_umask()
{
        local id score umask
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        umask=$(egrep -c "\s+umask\s+[0-9]" /etc/bashrc)
        [ $(grep "umask" /etc/bashrc | egrep -c "0[0-2][0-7]") -eq ${umask} ] && score=$((score+1))
        [ $(grep "umask" /etc/profile /etc/profile.d/*.sh | egrep -c "0[0-7][3-7]") -eq ${umask} ] && score=$((score+1))
        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function root_umask()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(grep -Psi -- '^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc |wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function root_passwd()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [[ $(passwd -S root|grep -q "Password set" ; echo $?) -eq 0 ]] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function nologin_shells()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(grep '/nologin\b' /etc/shells ; echo $?) -eq 1 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

##-- Su Command --##
function su_access()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su | wc -l) -eq 1 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}


                ## -- CHAPTER SIX -- ##
## -- SYSTEM FILE PERMISSIONS -- ##
function file_perm()
{
        local id score file perm
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        file=$6
        perm=$7
        score=0

        #= TEST =#
        [ $(stat ${file} | egrep "^Access:\s+\(${perm}\/\S+" | wc -l) -ne 0 ] && score=$((score+1))
        [ $(stat ${file} | egrep -o "0\/\s+root" | wc -l) -eq 2 ] && score=$((score+1))

        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}


function no_exist()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        l_output="" l_output2=""
        a_path=(); a_arr=(); a_nouser=(); a_nogroup=() # Initialize arrays
        a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "/sys/fs/cgroup/memory/*")
        while read -r l_bfs; do
                a_path+=( -a ! -path ""$l_bfs"/*")
        done < <(findmnt -Dkerno fstype,target | awk '$1 ~ /^\s*(nfs|proc|smb)/ {print $2}')
        while IFS= read -r -d $'\0' l_file; do
                [ -e "$l_file" ] && a_arr+=("$(stat -Lc '%n^%U^%G' "$l_file")") && echo "Adding: $l_file"
        done < <(find / \( "${a_path[@]}" \) \( -type f -o -type d \) \( -nouser -o -nogroup \) -print0 2> /dev/null)
        while IFS="^" read -r l_fname l_user l_group; do # Test files in the array
                [ "$l_user" = "UNKNOWN" ] && a_nouser+=("$l_fname")
                [ "$l_group" = "UNKNOWN" ] && a_nogroup+=("$l_fname")
        done <<< "$(printf '%s\n' "${a_arr[@]}")"
        [[ ! (( ${#a_nouser[@]} > 0 )) ]] && score=$((score+1))
        [[ ! (( ${#a_nogroup[@]} > 0 )) ]] && score=$((score+1))

        [ $score -eq 2 ] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

## -- USER and GROUP SETTINGS -- ##
#Note: I ran out of ideals for naming my function so I will call it by id
function fn_6.2.0()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        [ $(awk -F: '($2 == "" )' /etc/shadow | wc -l) -eq 0 ] && result="Pass"

         write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function no_legacy()
{
        local id file
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        file=$6

        [ $(awk -F: '($2 != "x" ) { print $1 }' ${file} | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function root_path()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        l_output2=""
        l_pmask="0022"
        l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
        l_root_path="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
        unset a_path_loc && IFS=":" read -ra a_path_loc <<< "$l_root_path"
        grep -q "::" <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains a empty directory (::)"
        grep -Pq ":\h*$" <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains a trailing (:)"
        grep -Pq '(\h+|:)\.(:|\h*$)' <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains current working directory (.)"
        while read -r l_path; do
                if [ -d "$l_path" ]; then
                        while read -r l_fmode l_fown; do
                                [ "$l_fown" != "root" ] && score=$((score+1))
                                [ $(( $l_fmode & $l_pmask )) -gt 0 ] && score=$((score+1))
                        done <<< "$(stat -Lc '%#a %U' "$l_path")"
                else
                        score=$((score+1))
                fi
        done <<< "$(printf "%s\n" "${a_path_loc[@]}")"

        [ $score -eq 0 ] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function fn_6.2.5()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [ $(awk -F ":" '($3 == 0) {print}' /etc/passwd | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fn_6.2.6()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
                        dirperm=$(ls -ld $dir | cut -f1 -d" ")

                        [ $(echo $dirperm | cut -c6) == "-" ] || score=$((score+1))
                        [ $(echo $dirperm | cut -c8) == "-" ] || score=$((score+1))
                        [ $(echo $dirperm | cut -c9) == "-" ] || score=$((score+1))
                        [ $(echo $dirperm | cut -c10) == "-" ] || score=$((score+1))

                fi

        done

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function user_dot_files()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        l_output="" l_output2="" l_output3=""
        l_bf="" l_df="" l_nf="" l_hf=""
        l_valid_shells="^($( awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
        while read -r l_epu l_eph; do
                [[ -n "$l_epu" && -n "$l_eph" ]] && a_uarr+=("$l_epu $l_eph")
        done <<< "$(awk -v pat="$l_valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd)"
        file_access_chk()
        {
                l_facout2=""
                l_max="$( printf '%o' $(( 0777 & ~$l_mask)) )"
                if [ $(( $l_mode & $l_mask )) -gt 0 ]; then
                        l_facout2="$l_facout2\n - File: \"$l_hdfile\" is mode: \"$l_mode\" and should be mode: \"$l_max\" or more restrictive"
                fi
                if [[ ! "$l_owner" =~ ($l_user) ]]; then
                        l_facout2="$l_facout2\n - File: \"$l_hdfile\" owned by: \"$l_owner\" and should be owned by \"${l_user//|/ or }\""
                fi
                if [[ ! "$l_gowner" =~ ($l_group) ]]; then
                        l_facout2="$l_facout2\n - File: \"$l_hdfile\" group owned by: \"$l_gowner\" and should be group owned by \"${l_group//|/ or }\""
                fi
        }
        while read -r l_user l_home; do
                l_fe="" l_nout2="" l_nout3="" l_dfout2="" l_hdout2="" l_bhout2=""
                if [ -d "$l_home" ]; then
                        l_group="$(id -gn "$l_user" | xargs)"
                        l_group="${l_group// /|}"
                        while IFS= read -r -d $'\0' l_hdfile; do
                                while read -r l_mode l_owner l_gowner; do
                                        case "$(basename "$l_hdfile")" in
                                        .forward | .rhost )
                                                l_fe="Y" && l_bf="Y"
                                                l_dfout2="$l_dfout2\n - File: \"$l_hdfile\" exists" ;;
                                        .netrc )
                                                l_mask='0177'
                                                file_access_chk
                                                if [ -n "$l_facout2" ]; then
                                                        l_fe="Y" && l_nf="Y"
                                                        l_nout2="$l_facout2"
                                                else
                                                        l_nout3=" - File: \"$l_hdfile\" exists"
                                                fi ;;
                                        .bash_history )
                                                l_mask='0177'
                                                file_access_chk
                                                if [ -n "$l_facout2" ]; then
                                                        l_fe="Y" && l_hf="Y"
                                                        l_bhout2="$l_facout2"
                                                fi ;;
                                        * )
                                                l_mask='0133'
                                                file_access_chk
                                                if [ -n "$l_facout2" ]; then
                                                        l_fe="Y" && l_df="Y"
                                                        l_hdout2="$l_facout2"
                                                fi ;;
                                        esac
                                done <<< "$(stat -Lc '%#a %U %G' "$l_hdfile")"
                        done < <(find "$l_home" -xdev -type f -name '.*' -print0)
                fi
                if [ "$l_fe" = "Y" ]; then
                        l_output2="$l_output2\n - User: \"$l_user\" Home Directory: \"$l_home\""
                        [ -n "$l_dfout2" ] && l_output2="$l_output2$l_dfout2"
                        [ -n "$l_nout2" ] && l_output2="$l_output2$l_nout2"
                        [ -n "$l_bhout2" ] && l_output2="$l_output2$l_bhout2"
                        [ -n "$l_hdout2" ] && l_output2="$l_output2$l_hdout2"
                fi
                [ -n "$l_nout3" ] && l_output3="$l_output3\n - User: \"$l_user\" Home Directory: \"$l_home\"\n$l_nout3"
        done <<< "$(printf '%s\n' "${a_uarr[@]}")"
        unset a_uarr # Remove array
        [ -n "$l_output3" ] && l_output3=" - ** Warning **\n - \".netrc\" files should be removed unless deemed necessary\n and in accordance with local site policy:$l_output3"
        [ -z "$l_bf" ] && l_output="$l_output\n - \".forward\" or \".rhost\" files"
        [ -z "$l_nf" ] && l_output="$l_output\n - \".netrc\" files with incorrect access configured"
        [ -z "$l_hf" ] && l_output="$l_output\n - \".bash_history\" files with incorrect access configured"
        [ -z "$l_df" ] && l_output="$l_output\n - \"dot\" files with incorrect access configured"
        [ -n "$l_output" ] && l_output=" - No local interactive users home directories contain:$l_output"

        [ -z "$l_output2" ] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function user_home()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        l_output="" l_output2="" l_heout2="" l_hoout2="" l_haout2=""
        l_valid_shells="^($( awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
        unset a_uarr && a_uarr=() # Clear and initialize array
        while read -r l_epu l_eph; do # Populate array with users and user home location
                a_uarr+=("$l_epu $l_eph")
        done <<< "$(awk -v pat="$l_valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd)"
        while read -r l_user l_home; do
                if [ -d "$l_home" ]; then
                        l_mask='0027'
                        l_max="$( printf '%o' $(( 0777 & ~$l_mask)) )"
                        while read -r l_own l_mode; do
                                [ "$l_user" != "$l_own" ] && score=$((score+1))
                                [ $(( $l_mode & $l_mask )) -gt 0 ] && score=$((score+1))
                        done <<< "$(stat -Lc '%U %#a' "$l_home")"
                else
                        score=$((score+1))
                fi
        done <<< "$(printf '%s\n' "${a_uarr[@]}")"

        [ $score -eq 0 ] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function fn_6.2.8()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
                        for file in $dir/.[A-Za-z0-9]*;do
                                if [ ! -h "$file" -a -f "$file" ]; then
                                        fileperm=$(ls -ld $file | cut -f1 -d" ")

                                        [ "$(echo $fileperm | cut -c6)" == "-" ] || score=$((score+1))
                                        [ "$(echo $fileperm | cut -c9)" == "-" ] || score=$((score+1))
                                fi
                        done
                fi
        done

        [ $score -eq 0 ] && result="Pass"

         write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fn_6.2.9()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
                        if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
                                score=$((score+1))
                        fi

                fi
        done

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fn_6.2.10()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
                        if [ ! -h "$dir/.netrc" -a -f "$idr/.netrc" ]; then
                                score=$((score+1))
                        fi

                fi
        done

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fn_6.2.11()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
                        for file in $dir/.netrc; do
                                if [ ! -h "$file" -a -f "$file" ]; then
                                        fileperm=$(ls -ld $file |cut -f1 -d" ")

                                        [ $(echo $fileperm | cut -c5) == "-" ] || score=$((score+1))
                                        [ $(echo $fileperm | cut -c6) == "-" ] || score=$((score+1))
                                        [ $(echo $fileperm | cut -c7) == "-" ] || score=$((score+1))
                                        [ $(echo $fileperm | cut -c8) == "-" ] || score=$((score+1))
                                        [ $(echo $fileperm | cut -c9) == "-" ] || score=$((score+1))
                                        [ $(echo $fileperm | cut -c10) == "-" ] || score=$((score+1))

                                fi
                        done
                fi
        done

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fn_6.2.12()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                else
                        for file in $dir/.rhosts; do
                                if [ ! -h "$file" -a -f "$file" ]; then
                                        score=$((score+1))
                                fi
                        done

                fi
        done

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fn_6.2.13()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        for i in $(cut -s -d: -f4 /etc/passwd | sort -u); do
                [ $(grep -q -P "^.*?:[^:]*:$i:" /etc/group &> /dev/null; echo $?) -eq 0 ] || score=$((score+1))
        done

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fn_6.2.x()
{
        local id file para
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        file=$6
        para=$7

        #function written for id 6.2.14 - 6.2.17

        #= TEST =#
        [ $(cut -f${para} -d: ${file} | sort | uniq -c | awk '$1 > 1 {print}' | wc -l) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fn_6.2.18()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        shdw_gid=$( grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group | awk -F: '{print $3}')
        [ $( grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group | wc -l) -eq 0 ] && score=$((score+1))
        [ $(awk -F ":" '{$4 == "'$shdw_gid'"} {print}' /etc/passwd | wc -l) -eq 0 ] && score=$((score+1))

        [ $score -eq 2 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function fn_6.2.19()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do

                if [ ! -d "$dir" ]; then
                        score=$((score+1))
                fi

        done

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

                ##---------- LEVEL 2 ----------##
                ## -- CHAPTER ONE -- ##
##-- FILESYSTEM --##
function chk_partition()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        partition=$5

        #description: Ensure separate partition exist for relevant partition

        #= TEST =#
        [ $(findmnt -kn $partition | wc -l) -eq 1 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

##-- Mandatory Access Control (MAC) --##
function selinux_bootloader()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure SELinux is not disable in bootloader configuration

        #= TEST =#
        [ $(grep -E 'kernelopts=(\S+\s+)*(selinux=0|enforcing=0)+\b' /boot/grub2/grubenv &> /dev/null; echo $?) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function unconfn_srv()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure no unconfined services exist

        #=T TEST =#
        [ $(ps -eZ | grep unconfined_service_t &> /dev/null; echo $?) -ne 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function selinux_config()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #description: Ensure SELinux policy is configured && state is enforcing]

        #= TEST =#
        if [ "$id" == "1.5.1.3" ] ; then
                [ $(grep -E '^\s*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config &> /dev/null; echo $?) -eq 0 ] && score=$((score+1))
                [ $(sestatus | grep Loaded | grep targeted &> /dev/null; echo $?) -eq 0 ] && score=$((score+1))
                [ $score -eq 2 ] && result="Pass"
        elif [ "$id" == "1.5.1.4" ] ; then
                [ $(grep -E '^\s*SELINUX=(enforcing|permissive)' /etc/selinux/config &> /dev/null; echo $?) -eq 0 ] &&score=$((score+1))
                [ $(sestatus | grep -E 'enforcing|permissive' | wc -l) -ne 0 ] && score=$((score+1))
                [ $score -eq 2 ] && result="Pass"
        elif [ "$id" == "1.5.1.5" ] ; then
                [ $(grep -E '^\s*SELINUX=enforcing' /etc/selinux/config &> /dev/null; echo $?) -eq 0 ] &&score=$((score+1))
                [ $(sestatus | grep enforcing | wc -l) -ne 0 ] && score=$((score+1))
                [ $score -eq 2 ] && result="Pass"
        fi

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}


                ## -- CHAPTER FOUR -- ##
##-- CONFIGURE SYSTEM ACCOUNTING --##
function audit_proc()
{
        local id var
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6

        #= TEST =#
        [ $(grubby --info=ALL | grep -Po '\b$var\b' ; echo $?) -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function audit_conf1()
{
        local id score var
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6
        score=0

        #= TEST =#
        if [[ "$id" == "5.2.2.2" ]] ; then
                [[ "$(grep $var /etc/audit/auditd.conf)" =~ "keep_logs" ]] || score=$((score+1))
        elif [[ "$id" == "5.2.2.3" ]] ; then
                [[ $(grep -iP -- '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf | wc -l) -eq 0 ]] && score=$((score+1))
                [[ $(grep -iP -- '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf | wc -l) -eq 0 ]] && score=$((score+1))
        elif [[ "$id" == "5.2.2.4" ]] ; then
                [[ $(grep -iP -- '^\h*space_left_action\h*=\h*(email|exec|single|halt)\b' /etc/audit/auditd.conf | wc -l) -eq 0 ]] && score=$((score+1))
                [[ $(grep -iP -- '^\h*admin_space_left_action\h*=\h*(single|halt)\b' /etc/audit/auditd.conf | wc -l) -eq 0 ]] && score=$((score+1))
        else
                [ $(grep -w "^\s*$var\s*=" /etc/audit/auditd.conf | wc -l) -eq 0 ] && score=$((score+1))
        fi

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function audit_conf2()
{
        local id score var regex
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        var=$6
        regex=$7
        score=0

        #= TEST =#
        if [[ $regex -ne 1 ]]
        then
                [[ $(grep $var /etc/audit/rules.d/*.rules | wc -l) -ne 0 ]] || score=$((score+1))
                [[ $(auditctl -l | grep $var | wc -l) -ne 0 ]] || score=$((score+1))
                [[ $(grep $var /etc/audit/rules.d/*.rules | wc -l) -eq $(auditctl -l | grep $var | wc -l) ]] || score=$((score+1))
        else
                [[ $(grep -E "${var}" /etc/audit/rules.d/*.rules | wc -l) -ne 0 ]] || score=$((score+1))
                [[ $(auditctl -l | grep -E "${var}" | wc -l) -ne 0 ]] || score=$((score+1))
                [[ $(grep -E "${var}" /etc/audit/rules.d/*.rules | wc -l) -eq $(auditctl -l | grep -E "${var}" | wc -l) ]] || score=$((score+1))
        fi

        [ $score -eq 0 ] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function audit_perm()
{
        local id part arr
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        if [[ "$id" == "5.2.4.2" ]] ; then
                [[ $(find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f \( ! -perm 600 -a ! -perm 0400 -a ! -perm 0200 -a ! -perm 0000 -a ! -perm 0640 -a ! -perm 0440 -a ! -perm 0040 \) -exec stat -Lc "%n %#a" {} + | wc -l) -eq 0 ]] && result="Pass"
        elif [[ "$id" == "5.2.4.3" ]] ; then
                [[ $(find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f ! -user root -exec stat -Lc "%n %U" {} + | wc -l) -eq 0 ]] && result="Pass"
        elif [[ "$id" == "5.2.4.4" ]] ; then
                [[ $(grep -Piw -- '^\h*log_group\h*=\h*(adm|root)\b' /etc/audit/auditd.conf | wc -l) -eq 1 ]] && result="Pass"
        elif [[ "$id" == "5.2.4.5" ]] ; then
                [[ $(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec stat -Lc "%n %a" {} + | grep -Pv -- '^\h*\H+\h*([0,2,4,6][0,4]0)\h*$' | wc -l) -eq 1 ]] && result="Pass"
        elif [[ "$id" == "5.2.4.6" ]] ; then
                [[ $(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root | wc -l) -eq 0 ]] && result="Pass"
        elif [[ "$id" == "5.2.4.7" ]] ; then
                [[ $(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root | wc -l) -eq 0 ]] && result="Pass"
        elif [[ "$id" == "5.2.4.8" ]] ; then
                [[ $(stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$' | wc -l) -eq 0 ]] && result="Pass"
        elif [[ "$id" == "5.2.4.9" ]] ; then
                [[ $(stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+root\h*$' | wc -l) -eq 0 ]] && result="Pass"
        elif [[ "$id" == "5.2.4.10" ]] ; then
                [[ $(stat -c "%n %a %U %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h+root\h+root\h*$' | wc -l) -eq 0 ]] && result="Pass"
        fi
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function audit_run_conf()
{
        local id part arr
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #= TEST =#
        [[ "$(augenrules --check)" == "/sbin/augenrules: No change" ]] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function audit_conf3()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
        if [[ "$id" == "5.2.3.1" ]] ; then
                [[ $(awk '/^ *-w/&&(/\/var\/run\/utmp/||/\/var\/log\/wtmp/||/\/var\/log\/btmp/)&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | wc -l) -eq 2 ]] || score=$((score+1))
        elif [[ "$id" == "5.2.3.2" ]] ; then
                [[ $(awk '/^ *-a *always,exit/&&/ -F *arch=b(32|64)/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&(/ -C *euid!=uid/||/ -C *uid!=euid/)&&/ -S *execve/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | wc -l) -eq 2 ]] || score=$((score+1))
        elif [[ "$id" == "5.2.3.3" ]] ; then
                SUDO_LOG_FILE_ESCAPED=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g')
                if [ -n "${SUDO_LOG_FILE_ESCAPED}" ] ; then
                        [[ $(awk "/^ *-w/&&/"${SUDO_LOG_FILE_ESCAPED}"/&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 1 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        elif [[ "$id" == "5.2.3.4" ]] ; then
                [[ $(awk '/^ *-a *always,exit/&&/ -F *arch=b(32|64)/&&/ -S/&&(/adjtimex/||/settimeofday/||/clock_settime/ )&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | wc -l) -eq 2 ]] || score=$((score+1))
                [[ $(awk '/^ *-w/&&/\/etc\/localtime/&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | wc -l) -eq 1 ]] || score=$((score+1))
        elif [[ "$id" == "5.2.3.5" ]] ; then
                [[ $(awk '/^ *-a *always,exit/&&/ -F *arch=b(32|64)/&&/ -S/&&(/sethostname/||/setdomainname/)&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules| wc -l) -eq 2 ]] || score=$((score+1))
                [[ $(awk '/^ *-w/&&(/\/etc\/issue/||/\/etc\/issue.net/||/\/etc\/hosts/||/\/etc\/sysconfig\/network/)&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules| wc -l) -eq 5 ]] || score=$((score+1))
        elif [[ "$id" == "5.2.3.7" ]] ; then
                if [ -n "${UID_MIN}" ] ; then
                        [[ $(awk "/^ *-a *always,exit/&&/ -F *arch=b(32|64)/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&/ -F *auid>=${UID_MIN}/&&(/ -F *exit=-EACCES/||/ -F *exit=-EPERM/)&&/ -S/&&/creat/&&/open/&&/truncate/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 4 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        elif [[ "$id" == "5.2.3.8" ]] ; then
                [[ $(awk '/^ *-w/&&(/\/etc\/group/||/\/etc\/passwd/||/\/etc\/gshadow/||/\/etc\/shadow/||/\/etc\/security\/opasswd/)&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | wc -l) -eq 5 ]] || score=$((score+1))
        elif [[ "$id" == "5.2.3.9" ]] ; then
                if [ -n "${UID_MIN}" ] ; then
                        [[ $(awk "/^ *-a *always,exit/&&/ -F *arch=b(32|64)/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&/ -S/&&/ -F *auid>=${UID_MIN}/&&(/chmod/||/fchmod/||/fchmodat/||/chown/||/fchown/||/fchownat/||/lchown/||/setxattr/||/lsetxattr/||/fsetxattr/||/removexattr/||/lremovexattr/||/fremovexattr/)&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 0 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        elif [[ "$id" == "5.2.3.10" ]] ; then
                if [ -n "${UID_MIN}" ] ; then
                        [[ $(awk "/^ *-a *always,exit/&&/ -F *arch=b(32|64)/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&/ -F *auid>=${UID_MIN}/&&/ -S/&&/mount/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 2 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        elif [[ "$id" == "5.2.3.11" ]] ; then
                [[ $(awk '/^ *-w/&&(/\/var\/run\/utmp/||/\/var\/log\/wtmp/||/\/var\/log\/btmp/)&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | wc -l) -eq 3 ]] || score=$((score+1))
        elif [[ "$id" == "5.2.3.12" ]] ; then
                [[ $(awk '/^ *-w/&&(/\/var\/log\/lastlog/||/\/var\/run\/faillock/)&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | wc -l) -eq 2 ]] || score=$((score+1))
        elif [[ "$id" == "5.2.3.13" ]] ; then
                if [ -n "${UID_MIN}" ] ; then
                        [[ $(awk "/^ *-a *always,exit/&&/ -F *arch=b(32|64)/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&/ -F *auid>=${UID_MIN}/&&/ -S/&&(/unlink/||/rename/||/unlinkat/||/renameat/)&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 2 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        elif [[ "$id" == "5.2.3.14" ]] ; then
                [[ $(awk '/^ *-w/&&(/\/etc\/selinux/||/\/usr\/share\/selinux/)&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules |wc -l) -eq 2 ]] || score=$((score+1))
        elif [[ "$id" == "5.2.3.15" ]] ; then
                if [ -n "${UID_MIN}" ] ; then
                        [[ $(awk "/^ *-a *always,exit/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&/ -F *auid>=${UID_MIN}/&&/ -F *perm=x/&&/ -F *path=\/usr\/bin\/chcon/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 1 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        elif [[ "$id" == "5.2.3.16" ]] ; then
                if [ -n "${UID_MIN}" ] ; then
                        [[ $(awk "/^ *-a *always,exit/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&/ -F *auid>=${UID_MIN}/&&/ -F *perm=x/&&/ -F *path=\/usr\/bin\/setfacl/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 1 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        elif [[ "$id" == "5.2.3.17" ]] ; then
                if [ -n "${UID_MIN}" ] ; then
                        [[ $(awk "/^ *-a *always,exit/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&/ -F *auid>=${UID_MIN}/&&/ -F *perm=x/&&/ -F *path=\/usr\/bin\/chacl/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 1 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        elif [[ "$id" == "5.2.3.18" ]] ; then
                if [ -n "${UID_MIN}" ] ; then
                        [[ $(awk "/^ *-a *always,exit/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&/ -F *auid>=${UID_MIN}/&&/ -F *perm=x/&&/ -F *path=\/usr\/sbin\/usermod/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 1 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        elif [[ "$id" == "5.2.3.19" ]] ; then
                [[ $(awk '/^ *-a *always,exit/&&/ -F *arch=b(32|64)/&&(/ -F auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/)&&/ -S/&&(/init_module/||/finit_module/||/delete_module/||/create_module/||/query_module/)&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | wc -l) -eq 1 ]] || score=$((score+1))
                if [ -n "${UID_MIN}" ] ; then
                        [[ $(awk "/^ *-a *always,exit/&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)&&/ -F *auid>=${UID_MIN}/&&/ -F *perm=x/&&/ -F *path=\/usr\/bin\/kmod/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules | wc -l) -eq 1 ]] || score=$((score+1))
                else
                        score=$((score+1))
                fi
        fi
        [ $score -eq 0 ] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function pcmd()
{
        local id part arr
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure use of privileged commands is collected
        #= TEST =#
        for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
                 for PRIVILEGED in $(find "${PARTITION}" -xdev -perm /6000 -type f); do
                         grep -qr "${PRIVILEGED}" /etc/audit/rules.d || score=$((score+1))
                 done
        done
        [ $score -eq 0 ] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function sulog_chk()
{
        local id score
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        [ $(grep -E "^\s*-w\s+$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//')\s+-p\s+wa\s+-k\s+actions" /etc/audit/rules.d/*.rules | wc -l) -ne 0 ] || score=$((score+1))
        [[ "$(auditctl -l | grep actions)" =~ "-w /var/log/sudo.log -p wa -k actions" ]] || score=$((score+1))
        [[ "$(echo "-w $(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//') -p wa -k actions")" =~ "-w /var/log/sudo.log -p wa -k actions" ]] || score=$((score+1))

        [ $score -eq 0 ] && result="Pass"

        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"

}

function audit_immutable()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5

        #description: Ensure the audit configuration is immutable

        #= TEST =#
        [ $( grep -Ph -- '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules | wc -l) -eq 1 ] && result="Pass"

         write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

function writable_files()
{
        local id
        level=$1
        chp=$2
        catid=$3
        id=$4
        descr=$5
        score=0

        #= TEST =#
        l_output="" l_output2=""
        l_smask='01000'
        a_path=(); a_arr=(); a_file=(); a_dir=() # Initialize arrays
        a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "/sys/kernel/security/apparmor/*" -a ! -path "/snap/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path "/sys/fs/selinux/*")
        while read -r l_bfs; do
                a_path+=( -a ! -path ""$l_bfs"/*")
        done < <(findmnt -Dkerno fstype,target | awk '$1 ~ /^\s*(nfs|proc|smb)/ {print $2}')
        while IFS= read -r -d $'\0' l_file; do
                [ -e "$l_file" ] && a_arr+=("$(stat -Lc '%n^%#a' "$l_file")")
        done < <(find / \( "${a_path[@]}" \) \( -type f -o -type d \) -perm -0002 -print0 2>/dev/null)
        while IFS="^" read -r l_fname l_mode; do # Test files in the array
                [ -f "$l_fname" ] && a_file+=("$l_fname") # Add WR files
                if [ -d "$l_fname" ]; then # Add directories w/o sticky bit
                        [ ! $(( $l_mode & $l_smask )) -gt 0 ] && a_dir+=("$l_fname")
                fi
        done < <(printf '%s\n' "${a_arr[@]}")
        [[ ! (( ${#a_file[@]} > 0 )) ]] && score=$((score+1))
        [[ ! (( ${#a_dir[@]} > 0 )) ]] && score=$((score+1))

        [ $score -eq 2 ] && result="Pass"
        write_result "$level" "$chp" "$catid" "$id" "$descr" "$result"
}

if [ $# -eq 0 ]; then
        usage
        exit 1
fi



                ##      Checking OPTIONS        ##
while :; do
        case $1 in
                -h|--help)
                        usage           #display the function usage
                        exit 0
                        ;;
                -ls|--list)
                        display         #list down the categories ID and name
                        exit 0
                        ;;
                -l|--level)
                        if [ ! -z "$2" ]; then
                                lvl=$2
                                shift
                                shift
                        else
                                echo "Error: did not indicate the level."
                                usage
                                exit 1
                        fi
                        ;;
                -e|--exclude)
                        if [ $2 ]; then
                                test_excluded $2
                                shift
                                shift
                        else
                                echo "Error: did not indicate the category id to be excluded from auditing."
                                usage
                                exit 1
                        fi
                        ;;
                -vv|--verbose)
                        verbose=1
                        shift
                        ;;
                -sh|--show)
                        show=1 #display result on table format
                        shift
                        ;;
                --)
                        shift
                        break
                        ;;
                *)
                        break
        esac
done

[ -z $lvl ] && all=1 #run both level 1 & 2


banner          #Display the banner function

                ###     Checking for Directories        ###
write_info "Checking of $LOG_DIR..."
sleep $tos

if [ -d "$LOG_DIR" ]
then
        write_debug "$LOG_DIR exists"
        if [ -d "$sub_logdir" ]
        then
                write_debug "$sub_logdir exists"
                sleep 0.25
        else
                write_debug "Creating $sub_logdir"
                mkdir "$sub_logdir"
                sleep 0.25
        fi

        if [ -d "$debug_dir" ]
        then
                write_debug "$debug_dir exists"
                sleep 0.25
        else
                write_debug "Creating $debug_dir"
                mkdir "$debug_dir"
        fi

else
        write_debug "Creating $LOG_DIR"
        mkdir "$LOG_DIR"

        write_debug "Creating subdirectories now...."
        sleep 0.5

        mkdir "$sub_logdir"
        write_debug "$sub_logdir is created"
        sleep 0.25

        mkdir "$debug_dir"
        write_debug "$sub_logdir is created"
        sleep 0.5

        write_info "Directories created..."
fi

                ### Creating DEBUG FILE under debug directories ###

if [ -e "$debug_dir/$debug_file" ]
then
        write_debug "$debug_file exists"
else
        write_debug "Creating $debug_file"
        touch "$debug_dir/$debug_file"

        write_info "Debug file created..."
fi

                ### Checking for JSON FILE      ###

if [ -e "$JSN_DIR/$JSN_FIL" ]
then
        cp "$JSN_DIR/$JSN_FIL" "$JSN_DIR/${JSN_FIL}.old"

elif [ -e "$JSN_DIR/${JSN_FIL}.old" ]
then
        cp "$JSN_DIR/${JSN_FIL}.old" "$JSN_DIR/${JSN_FIL}"

else
        echo "$(date -Ins) [ERROR] ${JSN_FIL} does not exists"
        exit 1
fi

[ -f $LOG_DIR/$FILE.log ] && rm $LOG_DIR/$FILE.log

                ###      MAIN    ###
write_info "Initiating....."
write_info "Audit Test Starting"

if [[ $lvl -eq 1  ]] || [[ $all -eq 1 ]] ; then
        ##--LEVEL 1--##
        #chp. 1 INITIAL SETUP
        #catg: filesystem
        write_info "catg: filesystem"
        if [[ !("${excl_arr1[@]}" =~ "1.1") ]] ; then
                run_test is_disabled     1 one 1.1 1.1.1.1   'Ensure cramfs kernel module is not available'         cramfs
                run_test is_disabled     1 one 1.1 1.1.1.2   'Ensure freevxfs kernel module is not available'       freevxfs
                run_test is_disabled     1 one 1.1 1.1.1.3   'Ensure hfs kernel module is not available'            hfs
                run_test is_disabled     1 one 1.1 1.1.1.4   'Ensure hfsplus kernel module is not available'        hfsplus
                run_test is_disabled     1 one 1.1 1.1.1.5   'Ensure jffs2 kernel module is not available'          jffs2
                run_test is_disabled     1 one 1.1 1.1.1.8   'Ensure usb-storage kernel module is not available'    usb-storage
                run_test tmp_config      1 one 1.1 1.1.2.1.1 'Ensure /tmp is a separte partition'
                run_test check_fs_nodev  1 one 1.1 1.1.2.1.2 'Ensure nodev option set on /tmp partition'            /tmp
                run_test check_fs_nosuid 1 one 1.1 1.1.2.1.3 'Ensure nosuid option set on /tmp partition'           /tmp
                run_test check_fs_noexec 1 one 1.1 1.1.2.1.4 'Ensure noexec option set on /tmp partition'           /tmp
                run_test chk_partition   1 one 1.1 1.1.2.2.1 'Ensure /dev/shm is a separte partition'               /dev/shm
                run_test check_fs_nodev  1 one 1.1 1.1.2.2.2 'Ensure nodev option set on /dev/shm partition'        /dev/shm
                run_test check_fs_nosuid 1 one 1.1 1.1.2.2.3 'Ensure nosuid option set on /dev/shm partition'       /dev/shm
                run_test check_fs_noexec 1 one 1.1 1.1.2.2.4 'Ensure noexec option set on /dev/shm partition'       /dev/shm
                run_test check_fs_nodev  1 one 1.1 1.1.2.3.2 'Ensure nodev option set on /home partition'           /home
                run_test check_fs_nosuid 1 one 1.1 1.1.2.3.3 'Ensure nosuid option set on /home partition'          /home
                run_test check_fs_nodev  1 one 1.1 1.1.2.4.2 'Ensure nodev option set on /var partition'            /var
                run_test check_fs_nosuid 1 one 1.1 1.1.2.4.3 'Ensure nosuid option set on /var partition'           /var
                run_test check_fs_nodev  1 one 1.1 1.1.2.5.2 'Ensure nodev option set on /var/tmp partition'        /var/tmp
                run_test check_fs_nosuid 1 one 1.1 1.1.2.5.3 'Ensure nosuid option set on /var/tmp partition'       /var/tmp
                run_test check_fs_noexec 1 one 1.1 1.1.2.5.4 'Ensure noexec option set on /var/tmp partition'       /var/tmp
                run_test check_fs_nodev  1 one 1.1 1.1.2.6.2 'Ensure nodev option set on /var/log partition'        /var/log
                run_test check_fs_nosuid 1 one 1.1 1.1.2.6.3 'Ensure nosuid option set on /var/log partition'       /var/log
                run_test check_fs_noexec 1 one 1.1 1.1.2.6.4 'Ensure noexec option set on /var/log partition'       /var/log
                run_test check_fs_nodev  1 one 1.1 1.1.2.7.2 'Ensure nodev option set on /var/log/audit partition'  /var/log/audit
                run_test check_fs_nosuid 1 one 1.1 1.1.2.7.3 'Ensure nosuid option set on /var/log/audit partition' /var/log/audit
                run_test check_fs_noexec 1 one 1.1 1.1.2.7.4 'Ensure noexec option set on /var/log/audit partition' /var/log/audit
        fi

        #catg: software_and_patch
        if [[ !("${excl_arr1[@]}" =~ "1.2") ]] ; then
                run_test not_scored 1 one 1.2 1.2.1 'Ensure GPG keys are configured'
                run_test gpg_check  1 one 1.2 1.2.2 'Ensure gpgcheck is globally activated'
                run_test not_scored 1 one 1.2 1.2.4 'Ensure package manager repositories are configured'
                run_test not_scored 1 one 1.2 1.2.5 'Ensure updates, patches, and additional security software are installed'
        fi

        #catg: secure_boot_settings
        if [[ !("${excl_arr1[@]}" =~ "1.3") ]] ; then
                run_test boot_passwd 1 one 1.3 1.3.1 'Ensure bootloader password is set'
                run_test boot_config 1 one 1.3 1.3.2 'Ensure permissions on bootloader config are configured'
        fi

        #catg: additional_process_hardening
        if [[ !("${excl_arr1[@]}" =~ "1.4") ]] ; then
                run_test alsr_enabled           1 one 1.4 1.4.1 'Ensure address space layout randomization is enabled'
                run_test ptrace_restricted      1 one 1.4 1.4.2 'Ensure ptrace_scope is restricted'
                run_test cd_backtraces_disabled 1 one 1.4 1.4.3 'Ensure core dump backtraces are disabled'
                run_test cd_storage_disabled    1 one 1.4 1.4.4 'Ensure core dump storage is disabled'
        fi

        #catg: MAC
        if [[ !("${excl_arr1[@]}" =~ "1.5") ]] ; then
                run_test chkpkg_installed   1 one 1.5 1.5.1.1 'Ensure SELinux is installed'                                     libselinux 1
                run_test selinux_bootloader 1 one 1.5 1.5.1.2 'Ensure SELinux is not disable in bootloader configuration'
                run_test selinux_config     1 one 1.5 1.5.1.3 'Ensure SELinux policy is configured'
                run_test selinux_config     1 one 1.5 1.5.1.4 'Ensure the SELinux mode is not disabled'
                run_test unconfn_srv        1 one 1.5 1.5.1.6 'Ensure no unconfined services exist'
                run_test chkpkg_installed   1 one 1.5 1.5.1.7 'Ensure the MCS Translation Services (mcstrans) is not installed' mcstrans 0
                run_test chkpkg_installed   1 one 1.5 1.5.1.8 'Ensure SETroubleshoot is not installed'                          setroubleshoot 0
        fi

        #catg: crypto
        if [[ !("${excl_arr2[@]}" =~ "1.6") ]] ; then
                run_test crypto_policy        1 one 1.6 1.6.1 'Ensure system wide crypto policy is not set to legacy' 1
                run_test crypto_disabled_sha1 1 one 1.6 1.6.2 'Ensure system wide crypto policy disables sha1 hash and signature support'
                run_test crypto_disabled_cbc  1 one 1.6 1.6.3 'Ensure system wide crypto policy disables cbc for ssh'
                run_test crypto_macs          1 one 1.6 1.6.4 'Ensure system wide crypto policy disables macs less than 128 bits'
        fi

        #catg: motd
        if [[ !("${excl_arr1[@]}" =~ "1.7") ]] ; then
                run_test motd_contens 1 one 1.7 1.7.1 'Ensure message of the day is configured properly'          /etc/motd
                run_test motd_contens 1 one 1.7 1.7.2 'Ensure local login warning banner is configured properly'  /etc/issue
                run_test motd_contens 1 one 1.7 1.7.3 'Ensure remote login warning banner is configured properly' /etc/issue.net
                run_test motd_config  1 one 1.7 1.7.4 'Ensure access to /etc/motd is configured'                  /etc/motd
                run_test motd_config  1 one 1.7 1.7.5 'Ensure access to /etc/issue is configured'                 /etc/issue
                run_test motd_config  1 one 1.7 1.7.6 'Ensure access to /etc/issue.net is configured'             /etc/issue.net
        fi

        #catg: gnome
        if [[ !("${excl_arr1[@]}" =~ "1.8") ]] ; then
                run_test gdm_config 1 one 1.8 1.8.2  'Ensure GDM login banner is configured'
                run_test not_scored 1 one 1.8 1.8.3  'Ensure GDM disable-user-list option is enabled'
                run_test not_scored 1 one 1.8 1.8.4  'Ensure GDM screen locks when the user is idle'
                run_test not_scored 1 one 1.8 1.8.5  'Ensure GDM screen locks cannot be overridden'
                run_test not_scored 1 one 1.8 1.8.6  'Ensure GDM automatic mounting of removable media is disabled'
                run_test not_scored 1 one 1.8 1.8.7  'Ensure GDM disabling automatic mounting of removable media is not overridden'
                run_test not_scored 1 one 1.8 1.8.8  'Ensure GDM autorun-never is enabled'
                run_test not_scored 1 one 1.8 1.8.9  'Ensure GDM autorun-never is not overridden'
                run_test not_scored 1 one 1.8 1.8.10 'Ensure XDMCP is not enabled'
        fi

        #----------------------------------#
        #chp. 2 SERVICES
        #catg: time synchronization
        if [[ !("${excl_arr1[@]}" =~ "2.1") ]] ; then
                run_test chkpkg_installed 1 two 2.1 2.1.1 'Ensure time syncrhonization is in use' chrony 1
                run_test chrony_config    1 two 2.1 2.1.2 'Ensure chrony is configured'
                run_test chrony_none_root 1 two 2.1 2.1.3 'Ensure chrony is not run as the root user'
        fi

        #catg: Special Purpose Services
        if [[ !("${excl_arr1[@]}" =~ "2.2") ]] ; then
                run_test chkpkg_installed 1 two 2.2 2.2.1  'Ensure autofs services are not in use'                autofs 0
                run_test chkpkg_installed 1 two 2.2 2.2.2  'Ensure avahi daemon services are not in use'          avahi 0
                run_test chkpkg_installed 1 two 2.2 2.2.3  'Ensure dhcp server services are not in use'           dhcp-server 0
                run_test chkpkg_installed 1 two 2.2 2.2.4  'Ensure dns server services are not in use'            bind 0
                run_test chkpkg_installed 1 two 2.2 2.2.5  'Ensure dnsmasq server services are not in use'        dnsmasq 0
                run_test chkpkg_installed 1 two 2.2 2.2.6  'Ensure samba server services are not in use'          samba 0
                run_test chkpkg_installed 1 two 2.2 2.2.7  'Ensure ftp server services are not in use'            vsftpd 0
                run_test chkpkg_installed 1 two 2.2 2.2.8  'Ensure message access server services are not in use' dovecot,cyrus-imapd 0
                run_test chkpkg_installed 1 two 2.2 2.2.9  'Ensure network file system services are not in use'   nfs-utils 0
                run_test chkpkg_installed 1 two 2.2 2.2.10 'Ensure nis server services are not in use'            ypserv 0
                run_test chkpkg_installed 1 two 2.2 2.2.11 'Ensure print server services are not in use'          cups 0
                run_test chkpkg_installed 1 two 2.2 2.2.12 'Ensure rpcbind services are not in use'               rpcbind 0
                run_test chkpkg_installed 1 two 2.2 2.2.13 'Ensure rsync services are not in use'                 rsync-daemon 0
                run_test chkpkg_installed 1 two 2.2 2.2.14 'Ensure snmp services are not in use'                  net-snmp 0
                run_test chkpkg_installed 1 two 2.2 2.2.15 'Ensure telnet server services are not in use'         telnet-server 0
                run_test chkpkg_installed 1 two 2.2 2.2.16 'Ensure tftp server services are not in use'           tftp-server 0
                run_test chkpkg_installed 1 two 2.2 2.2.17 'Ensure web proxy server services are not in use'      squid 0
                run_test chkpkg_installed 1 two 2.2 2.2.18 'Ensure web server services are not in use'            ttpd,nginx 0
                run_test chkpkg_installed 1 two 2.2 2.2.19 'Ensure xinetd services are not in use'                xinetd 0
                run_test mail_tagent      1 two 2.2 2.2.21 'Ensure mail transfer agents are configured for local-only mode'
                run_test not_scored       1 two 2.2 2.2.22 'Ensure only approved services are listening on a network interface'
        fi

        #catg: Service Clients
        if [[ !("${excl_arr1[@]}" =~ "2.3") ]] ; then
                run_test chkpkg_installed 1 two 2.3 2.3.1 'Ensure fts client is not installed'    ftp 0
                run_test chkpkg_installed 1 two 2.3 2.3.2 'Ensure ldap client is not installed'   openldap-clients 0
                run_test chkpkg_installed 1 two 2.3 2.3.3 'Ensure nis client is not installed'    ypbind 0
                run_test chkpkg_installed 1 two 2.3 2.3.4 'Ensure telnet client is not installed' telnet 0
                run_test chkpkg_installed 1 two 2.3 2.3.4 'Ensure tftp client is not installed'   tftp 0
        fi

        #----------------------------------#
        #chp. 3 NETWORK CONFIGURATION
        #catg: network devices
        if [[ !("${excl_arr2[@]}" =~ "3.1") ]] ; then
                run_test not_scored       1 three 3.3 3.1.1 'Ensure IPv6 status is identified'
                run_test wifi_config      1 three 3.3 3.1.2 'Ensure wireless interfaces are disabled'
                run_test chkpkg_installed 1 three 3.3 3.1.3 'Ensure bluetooth services are not in use' bluez 0
        fi

        #catg: network kernel modules
        if [[ !("${excl_arr1[@]}" =~ "3.3") ]] ; then
                run_test sysctl_1   1 three 3.3 3.3.1  'Ensure ip forwarding is disabled'              ip_forward 0 1 forwarding
                run_test sysctl_2   1 three 3.3 3.3.2  'Ensure packet redirect sending is disabled'    send_directs 0 0
                run_test sysctl_1   1 three 3.3 3.3.3  'Ensure bogus icmp responses are ignored'       icmp_ignore_bogus_error_responses 1 0
                run_test sysctl_1   1 three 3.3 3.3.4  'Ensure broadcast icmp requests are ignored'    icmp_echo_ignore_broadcasts 1 0
                run_test sysctl_2   1 three 3.3 3.3.5  'Ensure icmp redirects are not accepted'        accept_redirects 0 1
                run_test sysctl_2   1 three 3.3 3.3.6  'Ensure icmp redirects are not accepted'        secure_redirects 0 0
                run_test sysctl_2   1 three 3.3 3.3.7  'Ensure reverse path filtering is enabled'      rp_filter 1 0
                run_test sysctl_2   1 three 3.3 3.3.8  'Ensure source routed packets are not accepted' accept_source_route 0 1
                run_test sysctl_2   1 three 3.3 3.3.9  'Ensure suspicious packets are logged'          log_martians 1 0
                run_test sysctl_1   1 three 3.3 3.3.10 'Ensure tcp syn cookies is enabled'             tcp_syncookies 1 0
                run_test ipv6_route 1 three 3.3 3.3.11 'Ensure ipv6 route advertisements are not accepted'
        fi

        #catg: host based firewall
        if [[ !("${excl_arr1[@]}" =~ "3.4") ]] ; then
                run_test chkpkg_installed 1 three 3.4 3.4.1.1 'Ensure nftables is installed' nftables 1
                run_test fw_chkenabled    1 three 3.4 3.4.1.2 'Ensure a single firewall configuration utility is in use'
                run_test nft_2            1 three 3.4 3.4.2.1 'Ensure nftables base chains exist'
                run_test nft_3            1 three 3.4 3.4.2.2 'Ensure host based firewall loopback traffic is configured'
                run_test not_scored       1 three 3.4 3.4.2.3 'Ensure firewalld drops unnecessary services and ports'
                run_test not_scored       1 three 3.4 3.4.2.4 'Ensure nftables established connections are configured'
                run_test nft_2            1 three 3.4 3.4.2.5 'Ensure nftables default deny firewall policy' drop
        fi

        #----------------------------------#
        #chp. 4 ACCESS, AUTHENTICATION AND AUTHORIZATION
        #catg: job schedulers
        if [[ !("${excl_arr1[@]}" =~ "4.1") ]]; then
                run_test is_enabled 1 four 4.1 4.1.1.1 'Ensure cron daemon is enabled and active'               crond
                run_test file_perm  1 four 4.1 4.1.1.2 'Ensure permissions on /etc/crontab are configured'      /etc/crontab 0600
                run_test file_perm  1 four 4.1 4.1.1.3 'Ensure permissions on /etc/cron.hourly are configured'  /etc/cron.hourly 0700
                run_test file_perm  1 four 4.1 4.1.1.4 'Ensure permissions on /etc/cron.daily are configured'   /etc/cron.daily 0700
                run_test file_perm  1 four 4.1 4.1.1.5 'Ensure permissions on /etc/cron.weekly are configured'  /etc/cron.weekly 0700
                run_test file_perm  1 four 4.1 4.1.1.6 'Ensure permissions on /etc/cron.monthly are configured' /etc/cron.monthly 0700
                run_test file_perm  1 four 4.1 4.1.1.7 'Enusre permissions on /etc/cron.d are configured'       /etc/cron.d 0700
                run_test cron_perm  1 four 4.1 4.1.1.8 'Ensure crontab is restricted to authorized users'       cron
                run_test cron_perm  1 four 4.1 4.1.2.1 'Ensure at is restricted to authorized users'            at
        fi

        #catg: ssh server configuration
        if [[ !("${excl_arr1[@]}" =~ "4.2") ]]; then
                run_test file_perm      1 four 4.2 4.2.1  'Ensure permissions on /etc/ssh/sshd_config are configured'              /etc/ssh/sshd_config 0600
                run_test ssh_key_config 1 four 4.2 4.2.2  'Ensure permissions on SSH private host key files are configured'        0
                run_test ssh_key_config 1 four 4.2 4.2.3  'Ensure permissions on SSH public host key files are configured'         1
                run_test ssh_cfg_access 1 four 4.2 4.2.4  'Ensure sshd access is configured'
                run_test ssh_cfg_1      1 four 4.2 4.2.5  'Ensure sshd Banner is configured'                                       banner issue.net
                run_test ssh_cypher     1 four 4.2 4.2.6  'Ensure sshd Ciphers are configured'
                run_test ssh_cfg_2      1 four 4.2 4.2.7  'Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured' clientaliveinternal clientalivecountmax 15 3
                run_test ssh_cfg_1      1 four 4.2 4.2.9  'Ensure sshd HostbasedAuthentication is disabled'                        hostbasedauthentication no
                run_test ssh_cfg_1      1 four 4.2 4.2.10 'Ensure sshd IgnoreRhosts is enabled'                                    ignorerhosts yes
                run_test ssh_kexalgo    1 four 4.2 4.2.11 'Ensure sshd KexAlgorithms is configured'
                run_test ssh_cfg_1      1 four 4.2 4.2.12 'Ensure sshd LoginGraceTime is configured'                               logingracetime "[1-60]"
                run_test ssh_cfg_1      1 four 4.2 4.2.13 'Ensure sshd LogLevel is appropriate'                                    loglevel "(INFO|VERBOSE)"
                run_test ssh_macs       1 four 4.2 4.2.14 'Ensure sshd MACs are configured'
                run_test ssh_cfg_1      1 four 4.2 4.2.15 'Ensure sshd MaxAuthTries is configured'                                 maxauthtries "[1-4]"
                run_test ssh_cfg_1      1 four 4.2 4.2.16 'Ensure sshd MaxSessions is configured'                                  maxsessions "[1-10]"
                run_test ssh_cfg_1      1 four 4.2 4.2.17 'Ensure sshd MaxStartups is configured'                                  maxstartups 10:30:60
                run_test ssh_cfg_1      1 four 4.2 4.2.18 'Ensure sshd PermitEmptyPasswords is disabled'                           permitemptypasswords no
                run_test ssh_cfg_1      1 four 4.2 4.2.19 'Ensure sshd PermitRootLogin is disabled'                                permitrootlogin no
                run_test ssh_cfg_1      1 four 4.2 4.2.20 'Ensure sshd PermitUserEnvironment is disabled'                          permituserenvironment no
                run_test ssh_cfg_1      1 four 4.2 4.2.21 'Ensure sshd UsePAM is enabled'                                          usepam yes
                run_test ssh_crypto     1 four 4.2 4.2.22 'Ensure sshd crypto_policy is not set'
        fi

        #catg: privilege escalation
        if [[ !("${excl_arr1[@]}" =~ "4.3") ]]; then
                run_test chkpkg_installed 1 four 4.3 4.3.1 'Ensure sudo is installed'                                                   sudo 1
                run_test sudo_pty         1 four 4.3 4.3.2 'Ensure sudo commands use pty'
                run_test sudo_log         1 four 4.3 4.3.3 'Ensure sudo log file exists'
                run_test sudoers_cfg      1 four 4.3 4.3.5 'Ensure re-authentication for privilege escalation is not disabled globally' "^[^'].*\!authenticate"
                run_test sudoers_cfg      1 four 4.3 4.3.6 'Ensure sudo authentication timeout is configured correctly'                 "timestamp_timeout=\K[0-9]*"
                run_test su_access        1 four 4.3 4.3.7 'Ensure access to su command is restricted'
        fi

        #catg: configure pam
        if [[ !("${excl_arr1[@]}" =~ "4.4") ]]; then
                run_test chkpkg_installed 1 four 4.4 4.4.1.1   'Ensure latest version of pam is installed'             pam 1
                run_test chkpkg_installed 1 four 4.4 4.4.1.2   'Ensure latest version of pam is installed'             authselect 1
                run_test not_scored       1 four 4.4 4.4.2.1   'Ensure active authselect profile includes pam modules'
                run_test pam_config       1 four 4.4 4.4.2.2   'Ensure pam_faillock module is enabled'                 pam_faillock
                run_test pam_config       1 four 4.4 4.4.2.3   'Ensure pam_pwquality module is enabled'                pam_pwquality
                run_test pam_config       1 four 4.4 4.4.2.4   'Ensure pam_pwhistory module is enabled'                pam_pwhistory
                run_test pam_config       1 four 4.4 4.4.2.4   'Ensure pam_unix module is enabled'                     pam_unix
                run_test not_scored       1 four 4.4 4.4.3.1.1 'Ensure password failed attempts lockout is configured'
                run_test not_scored       1 four 4.4 4.4.3.1.2 'Ensure password unlock time is configured'
                run_test not_scored       1 four 4.4 4.4.3.2.1 'Ensure password number of changed characters is configured'
                run_test not_scored       1 four 4.4 4.4.3.2.2 'Ensure password length is configured'
                run_test not_scored       1 four 4.4 4.4.3.2.3 'Ensure password complexity is configured'
                run_test not_scored       1 four 4.4 4.4.3.2.4 'Ensure password same consecutive characters is configured'
                run_test not_scored       1 four 4.4 4.4.3.2.5 'Ensure password maximum sequential characters is configured'
                run_test not_scored       1 four 4.4 4.4.3.2.6 'Ensure password dictionary check is enabled'
                run_test not_scored       1 four 4.4 4.4.3.2.7 'Ensure password quality is enforced for the root user'
                run_test not_scored       1 four 4.4 4.4.3.3.1 'Ensure password history remember is configured'
                run_test not_scored       1 four 4.4 4.4.3.3.2 'Ensure password history is enforced for the root user'
                run_test not_scored       1 four 4.4 4.4.3.3.3 'Ensure pam_pwhistory includes use_authtok'
                run_test not_scored       1 four 4.4 4.4.3.4.1 'Ensure pam_unix does not include nullok'
                run_test not_scored       1 four 4.4 4.4.3.4.2 'Ensure pam_unix does not include remember'
                run_test not_scored       1 four 4.4 4.4.3.4.3 'Ensure pam_unix includes a strong password hashing algorithm'
                run_test not_scored       1 four 4.4 4.4.3.4.4 'Ensure pam_unix includes use_authtok'
        fi

        #catg: user accounts and environment
        if [[ !("${excl_arr1[@]}" =~ "4.5") ]]; then
                run_test strong_pwd     1 four 4.5 4.5.1.1 'Ensure strong password hashing algorithm is configured'
                run_test uae_cfg        1 four 4.5 4.5.1.2 'Ensure password expiration is 365 days or less'            ^PASS_MAX_DAYS 365
                run_test uae_cfg        1 four 4.5 4.5.1.3 'Ensure password expiration warning days is 7 or more'      ^PASS_WARN_AGE 7 6
                run_test uae_cfg        1 four 4.5 4.5.1.4 'Ensure inactive password lock is 30 days or less'          INACTIVE 30 7
                run_test pwd_cfg        1 four 4.5 4.5.1.5 'Ensure all users last password change date is in the past'
                run_test def_grp_access 1 four 4.5 4.5.2.1 'Ensure default group for the root account is GID 0'
                run_test root_umask     1 four 4.5 4.5.2.2 'Ensure root user umask is configured'
                run_test sysacc_secured 1 four 4.5 4.5.2.3 'Ensure system accounts are secured'
                run_test root_passwd    1 four 4.5 4.5.2.4 'Ensure root password is set'
                run_test def_usr_tmout  1 four 4.5 4.5.3.2 'Ensure default user shell timeout is configured'
                run_test def_usr_umask  1 four 4.5 4.5.3.3 'Ensure default user umake is configured'
        fi

        #----------------------------------#
        #chp. 5 LOGGING AND AUDITING
        #catg: configure logging
        if [[ !("${excl_arr1[@]}" =~ "5.1") ]]; then
                run_test chkpkg_installed 1 five 5.1 5.1.1.1   'Ensure rsyslog is installed'                                            rsyslog 1
                run_test is_enabled       1 five 5.1 5.1.1.2   'Ensure rsyslog service is enabled'                                      rsyslog
                run_test journald_cfg     1 five 5.1 5.1.1.3   'Ensure journald is configured to send logs to rsyslog'
                run_test rsyslog_perm     1 five 5.1 5.1.1.4   'Ensure rsyslog default file permissions configured'
                run_test not_scored       1 five 5.1 5.1.1.5   'Ensure logging is configured'
                run_test not_scored       1 five 5.1 5.1.1.6   'Ensure rsyslog is configured to send logs to a remote log host'
                run_test rsyslog_client   1 five 5.1 5.1.1.7   'Ensure rsyslog is not configured to receive logs from a remote client'
                run_test chkpkg_installed 1 five 5.1 5.1.2.1.1 'Ensure systemd-journal-remote is installed'                             systemd-journal-remote 1
                run_test not_scored       1 five 5.1 5.1.2.1.2 'Ensure systemd-journal-remote is configured'
                run_test is_enabled       1 five 5.1 5.1.2.1.3 'Ensure systemd-journal-remote is enabled'                               systemd-journal-remote
                run_test not_scored       1 five 5.1 5.1.2.1.4 'Ensure journald is not configured to receive logs from a remote client'
                run_test is_enabled       1 five 5.1 5.1.2.2   'Ensure journald service is enabled'                                     systemd-journald
                run_test journald_cfg     1 five 5.1 5.1.2.3   'Ensure journald is configured to compress large log files'
                run_test journald_cfg     1 five 5.1 5.1.2.4   'Ensure journald is configured to write logfiles to persistent disk'
                run_test not_scored       1 five 5.1 5.1.2.5   'Ensure journald is not configured to send logs to rsyslog'
                run_test not_scored       1 five 5.1 5.1.2.6   'Ensure journald log rotation is configured per site policy'
                run_test not_scored       1 five 5.1 5.1.3     'Ensure logrotate is configured'
                run_test permlog_cfg      1 five 5.1 5.1.4     'Ensure all logfiles have appropriate access configured'
        fi

        #catg: integrity checking
        if [[ !("${excl_arr1[@]}" =~ "5.3") ]]; then
                run_test chkpkg_installed  1 five 5.3 5.3.1 'Ensure AIDE is installed' aide 1
                run_test fs_periodic_check 1 five 5.3 5.3.2 'Ensure filesystem integirty is regularly checked'
                run_test aide_conf         1 five 5.3 5.3.3 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools'
        fi

        #----------------------------------#
        #chp. 6 SYSTEM MAINTENANCE
        #catg: system file permissions
        if [[ !("${excl_arr1[@]}" =~ "6.1") ]]; then
                run_test file_perm      1 six 6.1 6.1.1  'Ensure permissions on /etc/passwd are configured'           /etc/passwd "0[0-6][0|4][0|4]"
                run_test file_perm      1 six 6.1 6.1.2  'Ensure permissions on /etc/passwd- are configured'          /etc/passwd- "0[0-6][0|4][0|4]"
                run_test file_perm      1 six 6.1 6.1.3  'Ensure permissions on /etc/security/opasswd are configured' /etc/security/opasswd "0[0-6]00"
                run_test file_perm      1 six 6.1 6.1.4  'Ensure permissions on /etc/group are configured'            /etc/group "0[0-6][0|4][0|4]"
                run_test file_perm      1 six 6.1 6.1.5  'Ensure permissions on /etc/group- are configured'           /etc/group- "0[0-6][0|4][0|4]"
                run_test file_perm      1 six 6.1 6.1.6  'Ensure permissions on /etc/shadow are configured'           /etc/shadow 0000
                run_test file_perm      1 six 6.1 6.1.7  'Ensure permissions on /etc/shadow- are configured'          /etc/shadow- 0000
                run_test file_perm      1 six 6.1 6.1.8  'Ensure permissions on /etc/gshadow are configured'          /etc/gshadow 0000
                run_test file_perm      1 six 6.1 6.1.9  'Ensure permissions on /etc/gshadow- are configured'         /etc/gshadow- 0000
                run_test file_perm      1 six 6.1 6.1.10 'Ensure permissions on /etc/shells are configured'           /etc/shells "0[0-6][0|4][0|4]"
                run_test writable_files 1 six 6.1 6.1.11 'Ensure world writable files and directories are secured'
                run_test no_exist       1 six 6.1 6.1.12 'Ensure no unowned or ungrouped file or directories exist'
                run_test not_scored     1 six 6.1 6.1.13 'Ensure SUID and SGID files are reviewed'
        fi

        #catg: user and group settings
        if [[ !("${excl_arr1[@]}" =~ "6.2") ]]; then
                run_test no_legacy      1 six 6.2 6.2.1  'Ensure accounts in /etc/passwd use shadowed passwords' /etc/passwd
                run_test fn_6.2.0       1 six 6.2 6.2.2  'Ensure password fields are not empty'
                run_test fn_6.2.13      1 six 6.2 6.2.3  'Ensure all groups in /etc/passwd exist in /etc/group'
                run_test fn_6.2.x       1 six 6.2 6.2.4  'Enusre no duplicate UIDs exist'                        /etc/passwd 3
                run_test fn_6.2.x       1 six 6.2 6.2.5  'Ensure no duplicate GIDs exist'                        /etc/group 3
                run_test fn_6.2.x       1 six 6.2 6.2.6  'Ensure no duplicate user names exist'                  /etc/passwd 1
                run_test fn_6.2.x       1 six 6.2 6.2.7  'Ensure no duplicate group names exist'                 /etc/group 1
                run_test root_path      1 six 6.2 6.2.8  'Ensure root PATH Integrity'
                run_test fn_6.2.5       1 six 6.2 6.2.9  'Ensure root is the only UID 0 account'
                run_test user_home      1 six 6.2 6.2.10 'Ensure local interactive user home directories are configured'
                run_test user_dot_files 1 six 6.2 6.2.11 'Ensure local interactive user dot files access is configured'
        fi
fi

        ##########################################################################################
        ##########################################################################################

if [[ $lvl -eq 2 ]] || [[ $all -eq 1 ]] ; then

        ##--LEVEL 2--##
        #----------------------------------#
        #chp. 1 INITIAL SETUP
        #catg: filesystem
        if [[ !("${excl_arr2[@]}" =~ "1.1") ]]; then
                run_test is_disabled   2 one 1.1 1.1.1.6   'Ensure squashfs kernel module is not available' squashfs
                run_test is_disabled   2 one 1.1 1.1.1.7   'Ensure udf kernel module is not available'      udf
                run_test chk_partition 2 one 1.1 1.1.2.3.1 'Ensure /home is a separte partition'            /home
                run_test chk_partition 2 one 1.1 1.1.2.4.1 'Ensure /var is a separte partition'             /var
                run_test chk_partition 2 one 1.1 1.1.2.5.1 'Ensure /var/tmp is a separte partition'         /var/tmp
                run_test chk_partition 2 one 1.1 1.1.2.6.1 'Ensure /var/log is a separte partition'         /var/log
                run_test chk_partition 2 one 1.1 1.1.2.7.1 'Ensure /var/log is a separte partition'         /var/log/audit
        fi

        #catg: software_update
        if [[ !("${excl_arr2[@]}" =~ "1.2") ]]; then
                run_test repo_gpg_check 2 one 1.2 1.2.3 'Ensure repo_gpgcheck is globally activated'
        fi

        #catg: MAC
        if [[ !("${excl_arr1[@]}" =~ "1.5") ]]; then
                run_test selinux_config 2 one 1.5 1.5.1.5 'Ensure the SELinux mode is enforcing'
        fi

        #catg: crypto
        if [[ !("${excl_arr2[@]}" =~ "1.6") ]]; then
                run_test crypto_policy 2 one 1.6 1.3.0 'Ensure system-wide crypto policy is FUTURE or FIPS' 0
        fi

        #catg: gnome
        if [[ !("${excl_arr1[@]}" =~ "1.8") ]]; then
                run_test chkpkg_installed 2 one 1.8 1.8.1 'Ensure GNOME Display Manager is removed' gdm 0
                run_test not_scored       2 one 1.8 1.7.4 'Ensure updates, patches and additional security software'
        fi

        #----------------------------------#
        #chp. 2 SERVICES
        #catg: Special Purpose Services
        if [[ !("${excl_arr2[@]}" =~ "2.2") ]]; then
                run_test chkpkg_installed 2 two 2.2 2.3.20 'Ensure X windows server services are not in use' xorg-x11-server-common 0
        fi

        #----------------------------------#
        #chp. 3 NETWORK CONFIGURATION
        #catg: network kernel modules
        if [[ !("${excl_arr1[@]}" =~ "3.2") ]]; then
                run_test is_disabled 2 three 3.2 3.2.1 'Ensure dccp kernel module is not available' dccp
                run_test is_disabled 2 three 3.2 3.2.2 'Ensure tipc kernel module is not available' tipc
                run_test is_disabled 2 three 3.2 3.2.3 'Ensure rds kernel module is not available'  rds
                run_test is_disabled 2 three 3.2 3.2.4 'Ensure sctp kernel module is not available' sctp
        fi

        #catg: wireless configuration
        if [[ !("${excl_arr2[@]}" =~ "3.2") ]]; then
                run_test wifi_config 2 three 3.2 3.2.0 'Ensure wireless interfaces are disabled'

        fi

        #catg: disable ipv6
        if [[ !("${excl_arr2[@]}" =~ "3.3") ]]; then
                run_test not_scored 2 three 3.3 3.3.0 'Disable IPv6'
        fi

        #----------------------------------#
        #chp. 4 ACCESS, AUTHENTICATION AND AUTHORIZATION
        #catg: ssh server configuration
        if [[ !("${excl_arr2[@]}" =~ "4.2") ]]; then
                run_test ssh_cfg_1 2 four 4.2 4.2.8 'Ensure sshd DisableForwarding is enabled' disableforwarding yes
        fi

        #catg: privilege escalation
        if [[ !("${excl_arr1[@]}" =~ "4.3") ]]; then
                run_test sudoers_cfg 2 four 4.3 4.3.4 'Ensure users must provide password for escalation' "^[^'].*NOPASSWD"
        fi

        #catg: configure pam
        if [[ !("${excl_arr1[@]}" =~ "4.4") ]]; then
                run_test not_scored 2 four 4.4 4.4.3.1.3 'Ensure password failed attempts lockout includes root account'
        fi

        #catg: user accounts and environment
        if [[ !("${excl_arr1[@]}" =~ "4.5") ]]; then
                run_test nologin_shells 2 four 4.5 4.5.3.1 'Ensure nologin is not listed in /etc/shells'
        fi

        #----------------------------------#
        #chp. 5 LOGGING AND AUDITING
        #catg: configure system accounting
        if [[ !("${excl_arr2[@]}" =~ "5.2") ]]; then
                run_test chkpkg_installed 2 five 5.2 5.2.1.1  'Ensure auditd is installed'                                          audit 1
                run_test audit_proc       2 five 5.2 5.2.1.2  'Ensure auditing for processes that start prior to auditd is enabled' "audit=1"
                run_test audit_proc       2 five 5.2 5.2.1.3  'Ensure audit_backlog_limit is sufficient'                            "audit_backlog_limit=\S+"
                run_test is_enabled       2 five 5.2 5.2.1.4  'Ensure auditd service is enabled'                                    auditd
                run_test audit_conf1      2 five 5.2 5.2.2.1  'Ensure audit log storage size is configured'                         max_log_file
                run_test audit_conf1      2 five 5.2 5.2.2.2  'Ensure audit logs are not automatically deleted'                     keep_logs
                run_test audit_conf1      2 five 5.2 5.2.2.3  'Ensure system is disabled when audit logs are full'
                run_test audit_conf1      2 five 5.2 5.2.2.4  'Ensure system warns when audit logs are low on space'
                run_test audit_conf3      2 five 5.2 5.2.3.1  'Ensure changes to system administration scope (sudoers) is collected'
                run_test audit_conf3      2 five 5.2 5.2.3.2  'Ensure actions as another user are always logged'
                run_test audit_conf3      2 five 5.2 5.2.3.3  'Ensure events that modify the sudo log file are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.4  'Ensure events that modify date and time information are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.5  'Ensure events that modify the system's network environment are collected'
                run_test pcmd             2 five 5.2 5.2.3.6  'Ensure use of privileged commands are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.7  'Ensure unsuccessful file access attempts are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.8  'Ensure events that modify user/group information are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.9  'Ensure discretionary access control permission modification events are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.10 'Ensure successful file system mounts are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.11 'Ensure session initiation information is collected'
                run_test audit_conf3      2 five 5.2 5.2.3.12 'Ensure login and logout events are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.13 'Ensure file deletion events by users are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.14 'Ensure events that modify the system's Mandatory Access Controls are collected'
                run_test audit_conf3      2 five 5.2 5.2.3.15 'Ensure successful and unsuccessful attempts to use the chcon command are recorded'
                run_test audit_conf3      2 five 5.2 5.2.3.16 'Ensure successful and unsuccessful attempts to use the setfacl command are recorded'
                run_test audit_conf3      2 five 5.2 5.2.3.17 'Ensure successful and unsuccessful attempts to use the chacl command are recorded'
                run_test audit_conf3      2 five 5.2 5.2.3.18 'Ensure successful and unsuccessful attempts to use the usermod command are recorded'
                run_test audit_conf3      2 five 5.2 5.2.3.19 'Ensure kernel module loading unloading and modification is collected'
                run_test audit_immutable  2 five 5.2 5.2.3.20 'Ensure the audit configuration is immutable'
                run_test audit_run_conf   2 five 5.2 5.2.3.21 'Ensure the running and on disk configuration is the same'
                run_test file_perm        2 five 5.2 5.2.4.1  'Ensure the audit log directory is 0750 or more restrictive'          /etc/audit/rules.d 0750
                run_test audit_perm       2 five 5.2 5.2.4.2  'Ensure audit log files are mode 0640 or less permissive'
                run_test audit_perm       2 five 5.2 5.2.4.3  'Ensure only authorized users own audit log files'
                run_test audit_perm       2 five 5.2 5.2.4.4  'Ensure only authorized groups are assigned ownership of audit log files'
                run_test audit_perm       2 five 5.2 5.2.4.5  'Ensure audit configuration files are 640 or more restrictive'
                run_test audit_perm       2 five 5.2 5.2.4.6  'Ensure audit configuration files are owned by root'
                run_test audit_perm       2 five 5.2 5.2.4.7  'Ensure audit configuration files belong to group root'
                run_test audit_perm       2 five 5.2 5.2.4.8  'Ensure audit tools are 755 or more restrictive'
                run_test audit_perm       2 five 5.2 5.2.4.9  'Ensure audit tools are owned by root'
                run_test audit_perm       2 five 5.2 5.2.4.10 'Ensure audit tools belong to group root'
        fi

        #----------------------------------#
        #chp. 6 SYSTEM MAINTENANCE
        if [[ !("${excl_arr2[@]}" =~ "6.1") ]]; then
                run_test not_scored 2 six 6.1 6.1.14 'Audit system file permissions'
        fi
fi

write_info "Audit Test is done"
write_info "Script exited"
echo "Done..."
echo "-------------------------------------------------"
echo " "

if [[ $show -eq 1 ]]; then
        retrieve "${lvl}" "${all}"
fi

rename "$JSN_DIR" "$JSN_FIL"

unset excl_arr1
unset excl_arr2
