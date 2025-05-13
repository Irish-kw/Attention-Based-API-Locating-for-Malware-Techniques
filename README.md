# (IEEE TIFS) Attention-Based API Locating for Malware Techniques

This paper presents APILI, an innovative approach
to behavior-based malware analysis that utilizes deep learning
to locate the API calls corresponding to discovered malware
techniques in dynamic execution traces. APILI defines mul-
tiple attentions between API calls, resources, and techniques,
incorporating MITRE ATT&CK framework, adversary tactics,
techniques and procedures, through a neural network. We employ
fine-tuned BERT for arguments/resources embedding, SVD for
technique representation, and several design enhancements, in-
cluding layer structure and noise addition, to improve the locating
performance. To the best of our knowledge, this is the first
attempt to locate low-level API calls that correspond to high-
level malicious behaviors (that is, techniques). Our evaluation
demonstrates that APILI outperforms other traditional and
machine learning techniques in both technique discovery and
API locating. These results indicate the promising performance
of APILI, thus allowing it to reduce the analysis workload.


## 2025-05-13:
We updated APILI to the latest version (**APILI_W11_py3129_torch251_cuda118**, download available [[here](https://1drv.ms/u/s!AmHd3ERrMbP0ybQhhBF_DlJQodRxJA?e=KF8U1s)]).
this version only used for predict MITRE ATT&CK techniques, and there is no training code, training code refer to the section labeled `## Training from sketch`.
- Windows 11  
- Python 3.12.9  
- PyTorch 2.5.1  
- CUDA 11.8  
- Tested on RTX 4060 laptop GPU  

See `installed_packages.txt` for the full conda environment list.

1. [Optional] Open `1_make_mist_ver_cuckoo_fixed.ipynb` to generate MIST-format data for a single sample (we provide `OperaSetup_win7.json`, obtained from Cuckoo Sandbox).  
2. Open `2_Predict.ipynb` and run all cells to predict MITRE ATT&CK techniques.  
3. For API locating for each predict techniques, refer to the section labeled `## Locating API call from predicted techniques`.




## Before 2025-05-13
## Prediction:
1. Get the trace(report) file (.json) from Cuckoo Sandbox.
2. Make mist file via OperaPrediction/make_mist_ver_cuckoo_fixed.ipynb
3. Prediction via OperaPrediction/Predict.ipynb

## Training from sketch
Download Dataset / training code / ckp / result in paper 

https://1drv.ms/f/s!AmHd3ERrMbP0xdlAzJXkvK66qknzsQ?e=FfeWtY

1. src/Config_bert.json,  modify the path for your location
2. Make dataset, you can either use doc2vec or bert, present in the paper.
   
   2-1.MakeData_1_doc2vec_train.py

   2-2.MakeData_2_make_dataset.py

   2-3.MakeData_3_PCA_TTP_latent_vector.py

4. src/train_supervised.py, cd to the src/ and use the command to training, "python train_supervised.py --gpu 0 --type bert"
5. args.freeze and args.cp are disuse for this version.

## Locating api call from predict techniques

1. You can extract attention values from the prediction by following the paper's instructions.
   
2. To prevent it from falling into the hands of those who intend to use it for malicious purposes (e.g. adversarial training),
   If you want to reproduce the results of the paper, please open issus and provide your university/laboratory/school email address
   
3. The current locating code is a beta version that can only reproduce the results presented in the paper.
   To handle unseen malware, modifications are needed to enable the code to function without retraining the model.
