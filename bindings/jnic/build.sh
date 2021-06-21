if [[ "$JAVA_HOME" == '' ]]; then
	export JAVA_HOME=$(/usr/libexec/java_home)
	echo "set"
fi

gcc -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin/" -o libcapstonejni.jnilib -Wno-pointer-sign -shared -L../.. -lcapstone  capstone_jni.c