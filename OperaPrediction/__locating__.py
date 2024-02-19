class simulate_args():
    def __init__(self, model_type, is_freeze, is_tanh, is_cp, gpu = 'No'):
        self.freeze = str(is_freeze)
        self.tanh = str(is_tanh)
        self.cp = str(is_cp)
        self.type = str(model_type)
        self.gpu = str(gpu)
        
        super(simulate_args, self).__init__()