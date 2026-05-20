def calculate_risk(score):
    if score is None: # checks score is none / remeber score set to none earlier when a cve didnt have cvss score. case handled first so we dont try to compare none to a number.
        return 'Unknown' # if score is none returns unknown
    elif score >= 9.0: # checks score 9.0 above or else if it only runs the previous if was false. score of 9.0 above is consisdered critical severity according to cvss standard.
        return 'Critical'# score abaove 9.0 return critical.
    elif score >= 7.0: # checks score between 7.0 and 8.9
        return 'High' # if score between 7.0 / 8.9 return high.
    elif score >= 4.0:
        return 'Medium'
    else:
        return 'Low'
    
if __name__ == '__main__':
    test_scores = [9.5,7.2,4.5,2.1, None]
    for score in test_score:
        print(f"Score: {Score} -> Risk: {calculate_risk(score)}")