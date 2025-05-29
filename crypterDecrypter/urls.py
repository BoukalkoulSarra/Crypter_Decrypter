from django.urls import path
from . import views

urlpatterns = [
    path('',views.index, name="index"),
    path('chiffrement/', views.chiffCeser, name='chiffCesar'),
    path('dechiffrementCesar/', views.dechiffCeser, name="dechiffCeser"),
    path('atbush/', views.atbush_encrypt_view, name="atbush"),
    path('atbush/decrypt/', views.atbush_decrypt_view, name='atbush_decrypt'),
    path('Carré_Polybe/', views.crypter_carre_polybe, name='Carré_Polybe'),
    path('dechiffrement-polybe/', views.dechiffrer_carre_polybe, name='dech_Carré_Polybe'),
    path('ChiffVigenere/', views.encrypt_vigenere, name='ChiffVigenere'),
    path('dechVigenere/', views.decrypt_vigenere, name='dechVigenere'),
    path('vernamChiffrer/', views.vernam_encrypt, name='vernam_encrypt'),
    path('vernamDechiffrer/', views.vernam_decrypt, name='vernam_decrypt'),
    path('crypterautokey/', views.crypty_autokey, name='AutoKey'),
    path('decrypterkey/', views.decrypter_autokey, name='decrypterautokey'),
    path('encrypt_alberti/', views.encrypt_alberti, name='encryptAlberti'),
    path('dencrypt_alberti/', views.decrypt_alberti, name='dencryptAlberti'),
    path('encrypt_trithemius/', views.encrypt_trithemius, name='encryptTrithemius'),
    path('dencrypt_trithemius/', views.decrypt_trithemius, name='dencryptTrithemius'),
    path('encrypt_substitution/', views.encrypt_substitution, name='encryptSubstitution'),
    path('dencrypt_substitution/', views.decrypt_substitution, name='dencryptSubstitution'),
    path('encrypt_albam/', views.encrypt_albam, name='encryptAlbam'),
    path('decrypt_albam/', views.decrypt_albam, name='decryptAlbam'),
    path('encrypt_beaufort/', views.encrypt_beaufort, name='encryptBeaufort'),
    path('dencrypt_beaufort/', views.decrypt_beaufort, name='dencryptBeaufort'),
    path('encrypt_porta/', views.encrypt_porta, name='encryptPorta'),
    path('dencryptPorta/', views.decrypt_porta, name='dencryptPorta'),
    path('encrypt_Atbah/', views.encrypt_Atbah, name='encryptAtbah'),
    path('dencrypt_Atbah/', views.decrypt_Atbah, name='dencryptAtbah'),

]