import numpy as np
import pandas as pd
import xml.etree.ElementTree as ET

import json
import os
import pickle
import random
import logging
import glob
import re
import math
import time
import torch
import gc

from tqdm import tqdm
from dataset import APIDataset
from multiprocessing import Pool
from gensim.models.doc2vec import Doc2Vec
from py_stringmatching.tokenizer.delimiter_tokenizer import DelimiterTokenizer
from gensim.models import word2vec, fasttext

# from memory_profiler import profile

class Preprocessor:
    '''
    Args:
        data (list of str): all the api list [files, apis in file]
        label (list of int): label of the files
    '''
    def __init__(self, padded_len):

        self.arg2int = None

        self.padded_len = padded_len

        self.logging = logging.getLogger(name=__name__)

    def sigmoid(self, gamma):
        if gamma < 0:
            return 1 - 1/(1 + math.exp(gamma))
        else:
            return 1/(1 + math.exp(-gamma))

    def split_data(self, data_set, split_data_path):
        ''' Split training, validation and testing data
        '''
        hash_name_dict = { name.lower():i for i, (name, _, _) in enumerate(data_set) }

        tmp = glob.glob(os.path.join(split_data_path, '*'))
        for p in tmp:
            if 'train' in p:
                train_split = p
            elif 'valid' in p:
                valid_split = p
            elif 'test' in p:
                test_split = p

        with open(train_split, 'r') as f:
            train_hash_index = [ hash_name_dict[line.strip()] for line in f 
            if line.strip() in hash_name_dict.keys() ]

        with open(valid_split, 'r') as f:
            valid_hash_index = [ hash_name_dict[line.strip()] for line in f
            if line.strip() in hash_name_dict.keys() ]
            
        with open(test_split, 'r') as f:
            test_hash_index = [ hash_name_dict[line.strip()] for line in f
            if line.strip() in hash_name_dict.keys() ]



        train_set = []
        valid_set = []
        test_set = []

        for i in train_hash_index:
            train_set.append(data_set[i])
        for i in valid_hash_index:
            valid_set.append(data_set[i])
        for i in test_hash_index:
            test_set.append(data_set[i])

        print(len(train_set), len(valid_set), len(test_set))

        return train_set, valid_set, test_set

    def data_collected(self, data, data_label):

        train_hash, train_data, train_label = ([] for _ in range(3))

        key_list = list(data_label['sample'])
        ttp_dict = { i:ttp for i, ttp in enumerate(data_label.keys()[1:]) }

        trange = tqdm(data, total=len(data))
        for report in trange:
            (froot, fext) = os.path.splitext(report)
            # key = (malware hash)
            key = froot.split('/')[-1]
            if key.lower() in key_list:
                with open(report, 'r') as fp:
                    all_lines = fp.readlines()

                processed = {}
                for line in all_lines:
                    if '# process' in line:
                        process = line.split()[2]
                        processed[process] = []
                    else:
                        split = line.strip().split('|')

                        api_section = split[0]
                        if len(split) > 1:
                            arg_section ='|'.join(split[1:])
                        else:
                            arg_section = ''

                        cat, api = api_section.split()
                        args = arg_section.split(' b\'')
                        try:
                            cat = int(cat.strip(), 16)
                            api = int(api.strip(), 16)
                            if (cat == 9) or (api == 36):
                                continue
                            for i, _ in enumerate(args):
                                # eliminate b'str'
                                if args[i].startswith(' b"'):
                                    args[i] = args[i].split(' b"')[1]
                                if args[i].endswith("'"):
                                    args[i] = args[i].strip("'")
                                if args[i].startswith('0x'):
                                    args[i] = 'UNK'
                                else:
                                    args[i] = args[i].strip('\'').strip()

                            processed[process].append([cat]+[api]+args[1:])
                        except:
                            1


                processed = { process:calls for process, calls in processed.items() if calls != []}
                

                label = []
                for i, t in enumerate(data_label[data_label['sample']==key.lower()].values[0]):
                    if t==1:
                        label.append(ttp_dict[i-1])

                if processed != []:
                    train_hash.append( key.lower() )
                    train_data.append( processed )
                    train_label.append( label )


        return list(zip(train_hash, train_data, train_label)) 

    def data_processed(self, data, ttp_dict, config):

        with open(config['arg2int_path'], 'rb') as f:
            arg2int = pickle.load(f)
        with open(config['samples2res_path'], 'rb') as f:
            resrc_in_sample = pickle.load(f)
        resrc_in_sample = { k.lower():v for k, v in  resrc_in_sample.items() }    
            
        delimiters = ', ! ( ) [ ] @ : / . _ - \\ { } ; \' \" ~ | $ % # = + ‘ ’ < > ` & *'.split() + [' ']
        delim_tok = DelimiterTokenizer(delimiters)

        data_set = []
        samples2err_res = {}
        
        trange = tqdm(enumerate(data), total=len(data))
        for i, (name, tokens, label) in trange:
            processed = {}
            samples2err_res[name] = {}
            resrc_idx = resrc_in_sample[name]
            for proc in tokens.keys():
                if int(proc) in resrc_idx:
                    processed[proc] = {
                      'cat': [x[0] for x in tokens[proc]],
                      'api': [x[1] for x in tokens[proc]],
                      'args': [x[2:] for x in tokens[proc]],
                      'resrc': resrc_idx[int(proc)]
                      }
                elif str(proc).strip() in resrc_idx:
                    processed[proc] = {
                      'cat': [x[0] for x in tokens[proc]],
                      'api': [x[1] for x in tokens[proc]],
                      'args': [x[2:] for x in tokens[proc]],
                      'resrc': resrc_idx[str(proc).strip()]
                      }
            processed['name'] = name
            processed['label'] = label

            cat,api,args,args_nopadding_noembedding,resrcs, resrcs_nopadding_noembedding = ([] for _ in range(6))
            # # of process
            for proc_num, (k, v) in enumerate(processed.items()):
                if k not in ['name', 'label']:

                    # batch['cat']
                    cat.append(torch.tensor( v['cat'][ :min(self.padded_len, len(v['cat']))] + 
                        [9] * (self.padded_len - len(v['cat'])) ))

                    # batch['api']
                    api.append(torch.tensor( v['api'][ :min(self.padded_len, len(v['api']))] + 
                        [36] * (self.padded_len - len(v['api'])) ))

                    # batch['args']
                    tmp = self.tokens2emb(self.trim_pad( v['args'], self.padded_len), delim_tok, name)
                    args.append(tmp)
                    
                    tmp2 = self.tokens2emb2(self.trim_pad2( v['args'], self.padded_len), delim_tok, name)
                    args_nopadding_noembedding.append(tmp2)

                    del tmp, tmp2
                    
                    resrc, resrc_nopadding_noembedding = ([] for _ in range(2))
                    samples2err_res[name][proc_num] = set([])

                    for r in v['resrc']:
#                         tok = delim_tok.tokenize(str(r).strip('b\''))
                        tok = delim_tok.tokenize(str(r).strip()) #1003
                        words = ','.join(tok)
#                         #---------------------------------------------------------
#                         if words in arg2int.keys():
#                             resrc.append( str(arg2int[words]) )
#                             resrc_nopadding_noembedding.append( str(words) )
#                         elif words != '':
#                             print(name, proc_num, words)
#                             samples2err_res[name][proc_num] |= set( [words] )
#                         #---------------------------------------------------------        
                        #---------------------------------------------------------
                        if words in arg2int.keys(): 
                            if words.startswith(' b"'):
                                words = words.split(' b"')[1]
                                resrc.append( str(arg2int[words]) )
                                resrc_nopadding_noembedding.append( str(words) )                                
                            elif words.endswith("'"):
                                words = words.strip("'")
                                resrc.append( str(arg2int[words]) )
                                resrc_nopadding_noembedding.append( str(words) )
                            elif words.startswith('0x'):
                                resrc.append( str(arg2int['UNK']) )
                                resrc_nopadding_noembedding.append('UNK')
                            else:
                                resrc.append( str(arg2int[words]) )
                                resrc_nopadding_noembedding.append(words)
                        elif words != '':
                            samples2err_res[name][proc_num] |= set( [words] )
                    #---------------------------------------------------------
                        del words, tok

                    resrcs.append(list(set(resrc)))
                    resrcs_nopadding_noembedding.append(list(set(resrc_nopadding_noembedding)))
                    
            if (len(cat) !=0) and (len(api) !=0) and (len(args) !=0): #20210701 add this condition
                processed['cat'] = cat
                processed['api'] = api
                processed['args'] = args
                processed['args_nopadding_noembedding'] = args_nopadding_noembedding
                processed['resrc'] = resrcs
                processed['resrc_nopadding_noembedding'] = resrcs_nopadding_noembedding
                processed['y_len'] = len(processed['label'])
                processed['y'] = torch.zeros(1, len(ttp_dict))
                for TTP in processed['label']:
                    processed['y'][0, ttp_dict[TTP]] = 1
                data_set.append(processed)

        with open(config['sample2res_err_path'], 'wb') as f:
            pickle.dump(samples2err_res, f)


        return data_set


    def trim_pad(self, tokens, seq_len):

        tmp = [ token[:min(3, len(token))] + ['PAD'] * (3 - len(token)) for token in tokens ]

        return tmp[:min(seq_len, len(tmp))] + [['PAD'] * 3] * (seq_len - len(tmp))

    def trim_pad2(self, tokens, seq_len):

        tmp = [ token[:min(3, len(token))] + ['PAD'] * (3 - len(token)) for token in tokens ]

        return tmp
    
    
    def tokens2emb(self, tokens, delim_tok, name):

        indices = []

        for token in tokens:
            temp = []
            for t in token:
                if isinstance(t, str):
                    tok = delim_tok.tokenize(t)
                    words = ','.join(tok)

                    if words in self.arg2int.keys():
                        temp.append( str(self.arg2int[words]) )
                    else:
                        if words != '':
                            pass
#                             print(name, words)
                        temp.append( str(self.arg2int['UNK']) )

                else:
                    temp.append( float(t) )

            indices.append(temp)

        return indices

    def tokens2emb2(self, tokens, delim_tok, name):

        indices = []

        for token in tokens:
            temp = []
            for t in token:
                if isinstance(t, str):
                    tok = delim_tok.tokenize(t)
                    words = ','.join(tok)

                    if words in self.arg2int.keys():
                        temp.append( str(words) )
                    else:
                        if words != '':
                            pass
#                             print(name, words)
                        temp.append('UNK')

                else:
                    temp.append( float(t) )

            indices.append(temp)

        return indices    
    

    #@profile
    def make_cuckoo_dataset(self, mist_data_path, label_path, split_data_path, doc2vec_path, config):
        ''' make dataset for pytorch
        Return:
            dataset (torch.utils.data.Dataset)
        '''
        self.logging.info('preprocessing data...')
        reports = glob.glob(os.path.join(mist_data_path, '*.mist'))

        # data label load
        with open(label_path, 'rb') as f:
            data_label = pd.read_csv(f)

        # TTPs in whole dataset 
        ttps = list(data_label.keys())[1:]
        ttp_dict = { ttp: index for index, ttp in enumerate(sorted(ttps)) }

        data_set = self.data_collected(reports, data_label)
        
        train_set, valid_set, test_set = self.split_data(data_set, split_data_path)

        del data_set

        train_set = self.data_processed(train_set, ttp_dict, config)
        valid_set = self.data_processed(valid_set, ttp_dict, config)
        test_set = self.data_processed(test_set, ttp_dict, config)

        doc2Vec_model = np.load(doc2vec_path)
#         fast_model = np.load(fast_text_path)
        
        return APIDataset(train_set, ttp_dict, doc2Vec_model), \
        APIDataset(valid_set, ttp_dict, doc2Vec_model), \
        APIDataset(test_set, ttp_dict, doc2Vec_model)


    def save_dataset(self, train, valid, test, path):
        ''' save data to path/train.pkl, valid.pkl, test.pkl
        Args:
            train (torch.utils.data.Dataset) 
            test (torch.utils.data.Dataset)
            path (str): path to save data
        ''' 
        if not os.path.exists(path):
            os.mkdir(path)
            
        json_object = json.dumps(test.ttp_dict, indent=0)
        with open(os.path.join(path, 'ttp_dict.json'), "wb") as f:
            f.write(json_object.encode()) #encoder(), str to byte
        with open(os.path.join(path, 'train.pkl'), 'wb') as f:
            pickle.dump(train, f)
        with open(os.path.join(path, 'valid.pkl'), 'wb') as f:
            pickle.dump(valid, f)
        with open(os.path.join(path, 'test.pkl'), 'wb') as f:
            pickle.dump(test, f)

