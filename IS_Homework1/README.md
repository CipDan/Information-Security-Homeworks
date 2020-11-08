# Information Security Homework 1

1. The Key_Manager.py, Node_A.py and Node_B.py scripts are to be started one after the other in the given order, since Key_Manager.py creates the communication channels (in our case FIFOs) and Node_A.py acts as an intermediary between Key_Manager.py and Node_B.py.
2. The AES_Functions.py acts as a module with functions for implementing the ECB and CFB AES operation modes.
3. In AES_Functions.py we make use of pycryptodome's implementation of AES. For more information about __pycryptodome__ and how to configure: [pryptodome decription](https://pypi.org/project/pycryptodome/).
4. In Node_B.py we make use of the __python-magic__ module, which is a wrapper around the __libmagic__ C library, for determining the mime type of the file in which we store the encrypted message and associating to said file the right extension. For more details about python-magic and how to configure: [python-magic description](https://pypi.org/project/python-magic/).
5. In case you want to test only for text files, comment the marked section in Node_B.py where we use __python-magic__ and uncomment the marked __print__ commands in both Node_A.py and Node_B.py.
6. There are already two test files which can be used: mesage.txt and rata.bmp
