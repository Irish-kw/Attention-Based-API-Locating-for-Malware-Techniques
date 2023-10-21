from torch.utils.data import Dataset
from py_stringmatching.tokenizer.delimiter_tokenizer import DelimiterTokenizer
import numpy as np
import torch

class APIDataset(Dataset):
    '''
    Args:
        x (list of int): x data[sample, apis]
        y (list of int): y data[sample, label]
        padded_len (int): padding length
        padding (int): number to pad
    '''
    def __init__(self, data_set, ttp_dict, doc_model):
        self.data_set = data_set
        
        self.ttp_dict = ttp_dict
        self.doc_model = doc_model

    def __len__(self):
        return len(self.data_set)

    def __getitem__(self, idx):

        data_idx = self.data_set[idx]

        data = {
        'index':idx,
        'cat':data_idx['cat'],
        'api':data_idx['api'],
        'args':data_idx['args'],
#         'args_original':data_idx['args_nopadding_noembedding'],
        'resrc':data_idx['resrc'],
#         'resrc_original':data_idx['resrc_nopadding_noembedding'],
        'y_len':data_idx['y_len'],
        'y': data_idx['y'],
        'name': data_idx['name']
        }

        return data

    def collate_fn(self, datas):
        batch = {}
        batch['index'] = [ data['index'] for data in datas ]
        batch['proc_num'] = [len(data['cat']) for data in datas]
        batch['cat'] = torch.stack([ p for data in datas for p in data['cat'] ])
        batch['api'] = torch.stack([ p for data in datas for p in data['api'] ])
        batch['args'] = torch.stack([ self.tokens2emb(p, 'args') for data in datas for p in data['args'] ])
#         batch['args_original'] = torch.stack([ self.tokens2tokens(p) for data in datas for p in data['args'] ])
#         batch['resrc_original'] = [ p for data in datas for p in data['resrc'] ]
        batch['resrc'] = [ self.tokens2emb(p, 'resrc') for data in datas for p in data['resrc'] ]
        batch['resrc_num'] = [ len(r) for r in batch['resrc'] ]
        batch['y'] = torch.stack([ data['y'][0] for data in datas ])
        batch['y_len'] = [ data['y_len'] for data in datas ]
        batch['name'] = [ data['name'] for data in datas ]

        return batch

    def tokens2emb(self, tokens, data_type):
        

        if data_type == 'args':
            
            indices = []
            for token in tokens:
                temp = []

                for t in token:
                    if isinstance(t, str):
                        temp.append( list(self.doc_model[int(t)]) )
                    else:
                        temp.append( [float(t)] * self.doc_model.shape[1] )

                indices.append(temp)

        else:
            indices = [ list(self.doc_model[int(token)]) for token in (tokens) ]


        return torch.FloatTensor(indices)
    
    def tokens2tokens(self, tokens):
 
        indices = []
        for token in tokens:
            temp = []
            for t in token:
                temp.append( int(t) )
            indices.append(temp)
        return torch.IntTensor(indices)    