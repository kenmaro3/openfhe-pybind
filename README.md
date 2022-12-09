## OpenFHE + Pybind11
only few API is binded so far..


### install pybind via pip

```
pip install pybind11
```

### change one line in CMakeLists.txt

```
set(pybind11_DIR /home/kmihara/.pyenv/versions/3.7.4/envs/myenv/lib/python3.7/site-packages/pybind11)
```

to your path


### build

```
mkdir build
cd build
cmake ..
make -j4
```

### put so file into python package folder like

```
set(pybind11_DIR /home/kmihara/.pyenv/versions/3.7.4/envs/myenv/lib/python3.7/site-packages/pybind11)
```

### run test.py

```
python test.py
```

## few comments

- I found memory leaking, needs to be fixed
- only specific API is exported (basically CKKS)

if you see something like

```
cannot find libOPENFHEcore.so.1
```

you need to make sure openfhe-development is built,
and so file is in /usr/lib/ or /usr/local/lib
