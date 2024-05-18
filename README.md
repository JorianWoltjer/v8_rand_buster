# v8 `Math.random()` Cracker

Breaks the following pattern in the modern V8 JavaScript engine:

```js
Math.floor(MULTIPLE * Math.random())
```

Credits to [Douglas Goddard](https://github.com/TACIXAT/XorShift128Plus) for the initial work and blog post that helped explain how to solve this problem initially. This is an improved fork of [d0nutptr](https://github.com/d0nutptr/v8_rand_buster)'s implementation, where this fork adds a better CLI and the [blackbox_predict.py](blackbox_predict.py) script useful for when you lack source code, and want to quickly check if something is vulnerable.

# Usage

Assuming you've [watched the talk](https://www.youtube.com/watch?v=_Iv6fBrcbAM) and understand the nuances of how this works, the following should serve as a simple explanation that can get you going with this tool.

## 1. Getting samples

The first step is getting enough **consecutive sample outputs** of the generator function to let Z3 solve it. To get an idea of how many numbers you should get, a multiple of 10000 (4 digits) requires around 12 samples to be consistent. The more digits per sample, the less samples in total you require. 

Note that it is possible for your samples to lie on a 64-sized cache boundary where outputs are not sequential, so a useful trick is to get 2x the samples you would normally get (eg. 24 samples), and try to crack both the first and second half separately to make sure at least one does not lie on the boundary. The blackbox script already tries this and will find either half. 

In the following example, numbers are output after 60 calls, meaning there will be a boundary at the 4th sample, which we won't know. Then values are logged with an offset which is a common way of generating n-digit numbers without a 0-prefix:

```shell
$ node
> for(var i=0; i<60; i++) Math.random()
> for(var i=0; i<25; i++) console.log(Math.floor(9000 * Math.random()) + 1000)
4544
6785
...
8882
1404
```

## 2. Cracking the state

It is recommended to use the [blackbox_predict.py](blackbox_predict.py) script for finding a state from your samples as it tries a few permutations to try and find it in every possible edge case, doing the guessing for you. Save the samples in a newline-separated file and input it to the tool:

```bash
./blackbox_predict.py codes.txt
```

This will try a few permutations and tell you about them if it finds a correct state. For example:

````
Samples: [4544, 6785, 7436, 5880, 5293, 3121, 4752, 4744, 3512, 5539, 2523, 2503, 5056, 5306, 5529, 7082, 8661, 4812, 4919, 3535, 6655, 1307, 7784, 8882, 1404]
Guessing multiple from samples...
Multiple: 10000
Starting permutations...
--------------------------------------------------------------------------------
Permutation: ['reverse', 'offset', 'half_first']
Samples: [404, 7882, 6784, 307, 5655, 2535, 3919, 3812, 7661, 6082, 4529, 4306]
Multiple: 9000

Found states: 5885564196962522036,829032139228517597

- The samples were reversed. This is because the cache is a Last In First Out (LIFO) structure.
- The last half of your samples appear to be on a 64-wide cache boundary, therefore only the first half was used.
- The samples were offset by 1000 to make them n-digit numbers.
The following is likely how the generator is implemented:
```js
Math.floor(9000 * Math.random()) + 1000
```

Use the following command to predict new numbers:
./xs128p.py -s 5885564196962522036,829032139228517597 -m 9000 -a 1000 -g 5
````

The above explains that the samples were given in reverse, which happens because of the Last In First Out (LIFO) output of the cache. Then, it finds the multiple of 10000 was offset by 1000 to form the correct generator. It also gives the next command already to start predicting the new outputs.

## 3. Predicting outputs

The command it gave us above uses `-s` for the state, `-m` for the MULTIPLE value, `-a` for the offset, and `-g` to generate the next 5 outputs. Running the command we get 5 predictions starting from the cracked state:

```bash
Predictions (5):
1404
8882
7784
1307
6655
```

These outputs will have already added the `-a` value, so they should match up with your input in reverse. 

An important thing to note here is how the sequential xorshift128 values line up with the random outputs. The outputs are in the form of a **cache of 64 outputs**, which are read in a LIFO (Last-In First-Out) manner meaning from 64th to 1st. When it reaches the end, another set of 64 outputs is generated in one go starting from 64 again. This results in the samples coming out backwards, and a boundary of non-continuous numbers every 64 times. See the following diagram where XS128+ shows the raw output:

![image](https://github.com/JorianWoltjer/v8_rand_buster/assets/26067369/165237ac-d9fa-4acb-b050-26181d92c583)

If we remember the code used to generate these numbers, it started off by calling the random function 60 times, and then gave us 25 outputs. That means we did not receive the 60th-85th inputs, but instead, we received the 4th-1st and 128th to 108th inputs. We have cracked the state at index 108, and as seen above we can predict our inputs in reverse by iterating the random number generator from 108 to 128. After this, however, we get new values like index 129-192 which will only be output by the original program after passing the next cache boundary, as now it will generate the rest of 107-65 first. 

As you may imagine, calculating exactly where your predictions will happen gets a little tricky, but possible by comparing more outputs to a long string of predicted numbers from this program. You have the state after all, and you know every number that will ever be produced by the generator, the only tricky part is where the cache boundaries are that reset your reversed values. 

An easier prediction to make is **one before your samples** as in reality, it is likely to be the **next of your outputs**, as the generator is simply reversed 63/64 times. By cracking the state with the 2nd to 25th samples, and leaving the 1st as "unknown", we can predict it like so:

```js
> for(var i=0; i<10; i++) console.log(Math.floor(1000000 * Math.random()))
602281  // 64th ("unknown")
443830  // 63rd
839073  // ...
438933
766143
624388
225513
748023
426774
102458  // 55th
```

Saving the above `443830` to `102458` in `codes.txt`, we can crack the state again and predict 10 numbers from 9 inputs to get back the first "unknown" number:

```bash
$ ./blackbox_predict.py codes.txt

Found states: 6230255379373325501,1890031420000101351

./xs128p.py -s 6230255379373325501,1890031420000101351 -m 1000000 -g 10

Predictions (10):
102458
426774
748023
225513
624388
766143
438933
839073
443830
602281  # <-- Our 64th "unknown" number, predicted
```

After having cracked the state, you are able to predict the exact decimal numbers that `Math.random()` will preduce for as long as the generator lasts. If the generator is re-used in other places for harder-to-predict algorithms such a password generator, you can use the `xs128p()` and `to_double()` functions inside [xs128p.py](xs128p.py) to calculate those too from state values.
