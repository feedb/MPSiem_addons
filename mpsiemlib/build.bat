rmdir build
mkdir build
python setup.py bdist_wheel -d build
copy build\*.whl wheel