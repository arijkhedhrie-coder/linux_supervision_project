def calculer_metriques(df_clean):
    df_clean["Heure"] = df_clean["Date"].dt.floor("h")

    erreurs_par_heure = df_clean[df_clean["Etat"] == "Error"].groupby("Heure").size().reset_index()
    erreurs_par_heure.columns = ["Heure", "Nombre_Erreurs"]

    tentatives_par_ip = df_clean[df_clean["IP_Source"].notna()].groupby("IP_Source").size().reset_index()
    tentatives_par_ip.columns = ["IP_Source", "Nombre_Tentatives"]
    tentatives_par_ip = tentatives_par_ip.sort_values("Nombre_Tentatives", ascending=False)

    events_par_service = df_clean.groupby("Service").size().reset_index()
    events_par_service.columns = ["Service", "Nombre_Events"]
    events_par_service = events_par_service.sort_values("Nombre_Events", ascending=False)

    print("Metriques calculees")
    return erreurs_par_heure, tentatives_par_ip, events_par_service
