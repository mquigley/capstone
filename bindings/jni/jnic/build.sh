# To generate header file, use javac -h . -cp src/ src/capstone/Capstone.java

if [[ "$JAVA_HOME" == '' ]]; then
	JAVA_HOME=$(/usr/libexec/java_home)
	echo "set JAVA_HOME to $JAVA_HOME"
fi

#  -L../../.. -lcapstone -- link the capstone library
#gcc -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin/" -o libcapstonejni.jnilib -Wno-pointer-sign -shared -L../.. -lcapstone capstone_jni.c

gcc -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin/" -Wno-pointer-sign -shared -L../../.. -lcapstone -o ../bin/libcapstonejni.jnilib capstone_jni.c