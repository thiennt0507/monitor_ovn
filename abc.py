import numpy as np
import pandas as pd 
scores = [[0.1, 0.2], [0.4, 0.1]]
df = pd.DataFrame(scores)
df.to_csv("file.csv")