from loop import LocalOutlierProbability
import numpy as np


data =  np.array([
 [-0.685421751407983, -0.73115552984211407],
  [-0.685421751407983, -0.73115552984211407],
 [-2.3744241805625044, 1.3443896265777866]])

scores = LocalOutlierProbability(data, extent=0.997, n_neighbors=20).fit()
print(scores)