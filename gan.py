import os, time, itertools, imageio, pickle
import numpy as np
import matplotlib.pyplot as plt
import tensorflow as tf

# load MNIST
from tensorflow.examples.tutorials.mnist import input_data
mnist = input_data.read_data_sets("./mnist/data/", one_hot=True)

# G(z)
def generator(x):
    # initializers
    w_init = tf.random_normal_initializer(mean=0, stddev=0.01)
    b_init = tf.constant_initializer(0.)

    # 1st hidden layer
    w1 = tf.get_variable('G_w1', [x.get_shape()[1], 256], initializer=w_init)
    b1 = tf.get_variable('G_b1', [286], initializer=b_init)
    hidden = tf.nn.relu(tf.matmul(x, w1) + b1)

    # 2nd hidden layer
    w2 = tf.get_variable('G_w2', [hidden.get_shape()[1], 784], initializer=w_init)
    b2 = tf.get_variable('G_b2', [784], initializer=b_init)
    output = tf.nn.sigmoid(tf.matmul(hidden, w2) + b2)
    
    return output

# D(x)
def discriminator(x):

    # initializers
    w_init = tf.truncated_normal_initializer(mean=0, stddev=0.02)
    b_init = tf.constant_initializer(0.)

    # 1st hidden layer
    w1 = tf.get_variable('D_w1', [x.get_shape()[1], 256], initializer=w_init)
    b1 = tf.get_variable('D_b1', [256], initializer=b_init)
    hidden = tf.nn.relu(tf.matmul(x, w1) + b1)

    # 2nd hidden layer
    w2 = tf.get_variable('D_w1', [hidden.get_shape()[1], 1], initializer=w_init)
    b2 = tf.get_variable('D_b1', [1], initializer=b_init)
    output = tf.nn.relu(tf.matmul(hidden, w2) + b2)

    return output

def random_noise(batch_size):
    return np.random.normal(size=[batch_size, 128])


# training parameters
batch_size = 100
learning_rate = 0.0002
train_epoch = 100

# networks : generator
with tf.variable_scope('G'):
    z = tf.placeholder(tf.float32, shape=(None, 128))
    G_z = generator(z)

# networks : discriminator
with tf.variable_scope('D') as scope:
    x = tf.placeholder(tf.float32, shape=(None, 784))
    D_real = discriminator(x)
    scope.reuse_variables()
    D_fake = discriminator(G_z)


# loss for each network
D_loss = tf.reduce_mean(tf.log(D_real) + tf.log(1 - D_fake))
G_loss = tf.reduce_mean(tf.log(D_fake))

# trainable variables for each network
t_vars = tf.trainable_variables()
D_vars = [var for var in t_vars if 'D_' in var.name]
G_vars = [var for var in t_vars if 'G_' in var.name]

# optimizer for each network
D_train= tf.train.AdamOptimizer(learning_rate).minimize(-D_loss, var_list=D_vars)
G_train = tf.train.AdamOptimizer(learning_rate).minimize(-G_loss, var_list=G_vars)


# open session and initialize all variables
sess = tf.InteractiveSession()
tf.global_variables_initializer().run()

total_bath = int(mnist.train.num_examples/batch_size)
loss_d_, loss_g_ = 0, 0

# training-loop
for epoch in range(train_epoch):
    for iter in range(total_bath):
        # update discriminator
        batch_xs, _ = mnist.train.next_batch(batch_size)
        noise = get_noise(batch_size)

        _, loss_d_ = sess.run([D_train, D_loss], feed_dict = {x: batch_xs, z: noise})
        _, loss_g_ = sess.run([G_train, G_loss], feed_dict = {z: noise})
        
        print('Epoch: %04d' % epoch, 'D loss: {:.4}'.format(loss_d_), 'G loss: {:.4}'.format(loss_g_))
        
        # save images
        if epoch == 0 or (epoch + 1) % 10 == 0:
            sample_size = 10
            noise = get_noise(batch_size)
            samples = sess.run(G, feed_dict = {z: noise})
            
            fig, ax = plt.subplots(1, sample_size, figsize=(sample_size, 1))
            
            for i in range(sample_size):
                ax[i].set_axis_off()
                ax[i].imshow(np.reshape(samples[i], (28, 28)))
               
            plt.savefig('samples/{}.png'.format(str(epoch).zfill(3)), bbox_inches='tight')
            plt.close(fig)

print('end')
