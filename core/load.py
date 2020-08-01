import pickle

with open('probes.pkl', 'rb',) as f:
    data = pickle.load(f,encoding='latin1')
    
    #word_list = list(data.keys())
    print(data)
