# submask_cipher.py needed
# TODO: add exception
import submask_cipher as cryptsys

# jupyter and ipywidgets needed
import ipywidgets

def F():
    import ipywidgets as widgets
    from ipywidgets import HBox, VBox
    import numpy as np
    import matplotlib.pyplot as plt
    from IPython.display import display
    %matplotlib inline
    @widgets.interact
    
    # BOX 1  message
    # BOX 2  key
    def f(BOX1=widgets.Text(value='This is some text', disabled=False),
             BOX2=widgets.Text(value='totally a secure password lol', disabled=False)):
        plain_text = BOX1
        print(  data := cryptsys.encrypt(bytes(BOX1,'UTF-8'), # message
                                                bytes(BOX2,'UTF-8')))               # key
        
F()
