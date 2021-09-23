'''
Assignment Part - C
'''

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

REPORT_FILES = [
    'performance_report_mydig.csv',
    'performance_report_google_dns.csv',
    'performance_report_local_dns.csv'
]

def CDF(data):
    count, bins_count = np.histogram(data, bins = np.arange(0, 1600, 50))
    pdf = count / sum(count)
    cdf = np.cumsum(pdf)

    return bins_count[1:], cdf

if __name__ == '__main__':
    try:
        df_list = []
        first_col_added = False
        for FILE in REPORT_FILES:
            curr_df = pd.read_csv(FILE)

            if not first_col_added:
                df_list.append(curr_df)
                first_col_added = True
            else:
                curr_df = curr_df.iloc[:, 1].to_frame()
                df_list.append(curr_df)
    
        df = pd.concat(df_list, axis=1)

        '''Plot the CDFs'''
        plt.figure(figsize=(16,8))
        for column in df.columns[1:]:
            list = df[column].to_list()
            X, Y = CDF(list)
            plt.plot(X, Y)

        plt.legend(df.columns[1:], prop={'size': 10}, loc='lower right')
        plt.xlabel('Resolution time (msec)', fontsize=12)
        plt.ylabel('Pr[X <= x]', fontsize=12)
        plt.title('DNS Resolution time (CDF)', fontsize=16)
        x_axis = np.arange(0, 1600, 50)
        plt.xticks(x_axis, fontsize=8)
        y_axis = np.arange(0, 1.1, 0.1)
        plt.yticks(y_axis, fontsize=8)
        plt.show()

    except Exception as e:
        print(e)



