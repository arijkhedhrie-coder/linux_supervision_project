# Module de prevision - a completer
# Modele : ARIMA (Statsmodels)

def prevoir_erreurs(erreurs_par_heure, steps=6):
    from statsmodels.tsa.arima.model import ARIMA
    serie = erreurs_par_heure["Nombre_Erreurs"]
    modele = ARIMA(serie, order=(1, 1, 1))
    resultat = modele.fit()
    previsions = resultat.forecast(steps=steps)
    print(f"Prevision sur {steps} prochaines heures :")
    print(previsions)
    return previsions
