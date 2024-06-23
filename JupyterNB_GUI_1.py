import submask_cipher as cryptsys

import ipywidgets as widgets

@widgets.interact
def interactive_encrypt(
    message='This is some text',
    key='totally a secure password lol'
):
    return (cryptsys.encrypt(bytes(message,'UTF-8'), bytes(key,'UTF-8')))
