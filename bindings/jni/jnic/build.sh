if [[ "$JAVA_HOME" == '' ]]; then
	JAVA_HOME=$(/usr/libexec/java_home)
	echo "set JAVA_HOME to $JAVA_HOME"
fi

gcc -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin/" -o libcapstonejni.jnilib -Wno-pointer-sign -shared -L../.. -lcapstone  capstone_jni.c