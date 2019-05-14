package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/immesys/wave/consts"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/waved"
	"github.com/immesys/wavemq/mqpb"
	"github.com/stretchr/testify/require"
)

func getam() *AuthModule {
	rv := &waved.Configuration{
		Database:     "/tmp/waved",
		ListenIP:     "127.0.0.1:4410",
		HTTPListenIP: "127.0.0.1:4411",
		Storage:      make(map[string]map[string]string),
	}
	rv.Storage["default"] = make(map[string]string)
	rv.Storage["default"]["provider"] = "http_v1"
	rv.Storage["default"]["url"] = "https://standalone.storage.bwave.io/v1"
	rv.Storage["default"]["version"] = "1"
	am, err := NewAuthModule(rv)
	if err != nil {
		panic(err)
	}
	return am
}

var am *AuthModule

func init() {
	am = getam()
	InitEnclave()
}

func TestSubProof(t *testing.T) {
	ns, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ns.PublicDER,
	})
	ent, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ent.PublicDER,
	})
	attresp, err := am.wave.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ns.SecretDER,
			},
		},
		Publish:     true,
		SubjectHash: ent.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: ns.Hash,
				Statements: []*pb.RTreePolicyStatement{
					{
						PermissionSet: []byte(WAVEMQPermissionSet),
						Permissions:   []string{WAVEMQSubscribe},
						Resource:      "foo/bar",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)
	persp := &mqpb.Perspective{
		EntitySecret: &mqpb.EntitySecret{
			DER: ent.SecretDER,
		},
	}
	subreq, err := am.FormSubRequest(&mqpb.SubscribeParams{
		Perspective: persp,
		Namespace:   ns.Hash,
		Uri:         "foo/bar",
		Identifier:  "super-unique",
		Expiry:      120,
	}, "lol")
	require.NoError(t, err)
	err = am.CheckSubscription(subreq)
	require.Error(t, err)

	wavepersp := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: ns.SecretDER,
		},
	}
	am.provisionKey(wavepersp, ns.Hash)
	err = am.CheckSubscription(subreq)
	require.NoError(t, err)
}
func TestMessageNoProof(t *testing.T) {
	ns, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ns.PublicDER,
	})
	ent, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ent.PublicDER,
	})
	attresp, err := am.wave.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ns.SecretDER,
			},
		},
		Publish:     true,
		SubjectHash: ent.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: ns.Hash,
				Statements: []*pb.RTreePolicyStatement{
					{
						PermissionSet: []byte(WAVEMQPermissionSet),
						Permissions:   []string{WAVEMQPublish},
						Resource:      "foo/bar",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)

	persp := &mqpb.Perspective{
		EntitySecret: &mqpb.EntitySecret{
			DER: ent.SecretDER,
		},
	}
	msg, err := am.FormMessage(&mqpb.PublishParams{
		Perspective: persp,
		Namespace:   ns.Hash,
		Uri:         "foo/baz",
	}, "lol")
	require.NotNil(t, err)
	_ = msg
}

func BenchmarkFormMessage(b *testing.B) {
	ns, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(b, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ns.PublicDER,
	})
	ent, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(b, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ent.PublicDER,
	})
	attresp, err := am.wave.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ns.SecretDER,
			},
		},
		Publish:     true,
		SubjectHash: ent.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: ns.Hash,
				Statements: []*pb.RTreePolicyStatement{
					{
						PermissionSet: []byte(WAVEMQPermissionSet),
						Permissions:   []string{WAVEMQPublish},
						Resource:      "foo/bar",
					},
				},
			},
		},
	})
	require.NoError(b, err)
	require.Nil(b, attresp.Error)

	persp := &mqpb.Perspective{
		EntitySecret: &mqpb.EntitySecret{
			DER: ent.SecretDER,
		},
	}
	b.ResetTimer()
	content := []byte("hello world")
	fmt.Printf("===== BEGIN <<<<\n")
	for i := 0; i < b.N; i++ {
		msg, err := am.FormMessage(&mqpb.PublishParams{
			Perspective:         persp,
			Namespace:           ns.Hash,
			Uri:                 "foo/bar",
			Content:             []*mqpb.PayloadObject{{Schema: "text", Content: content}},
			EncryptionPartition: [][]byte{[]byte("foo"), []byte("bar")},
		}, "lol")
		require.NoError(b, err)
		_ = msg
	}
	fmt.Printf("===== END >>>>>>\n")
}
func TestMessage(t *testing.T) {
	ns, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ns.PublicDER,
	})
	ent, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ent.PublicDER,
	})
	attresp, err := am.wave.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ns.SecretDER,
			},
		},
		Publish:     true,
		SubjectHash: ent.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: ns.Hash,
				Statements: []*pb.RTreePolicyStatement{
					{
						PermissionSet: []byte(WAVEMQPermissionSet),
						Permissions:   []string{WAVEMQPublish},
						Resource:      "foo/bar",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)

	persp := &mqpb.Perspective{
		EntitySecret: &mqpb.EntitySecret{
			DER: ent.SecretDER,
		},
	}
	content := []byte("hello world")
	msg, err := am.FormMessage(&mqpb.PublishParams{
		Perspective: persp,
		Namespace:   ns.Hash,
		Uri:         "foo/bar",
		Content:     []*mqpb.PayloadObject{{Schema: "text", Content: content}},
	}, "lol")
	require.NoError(t, err)

	//validate
	try1 := am.CheckMessage(persp, msg)
	require.NoError(t, try1)
	try1 = am.CheckMessage(persp, msg)
	require.NoError(t, try1)
	try2 := am.DRCheckMessage(msg)
	fmt.Println(try2)
	require.Error(t, try2)

	wavepersp := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: ns.SecretDER,
		},
	}
	am.provisionKey(wavepersp, ns.Hash)
	//validate
	try2 = am.DRCheckMessage(msg)
	require.NoError(t, try1)
	try2 = am.DRCheckMessage(msg)
	require.NoError(t, try2)

	//prepare
	m, err := am.PrepareMessage(persp, msg)
	require.NoError(t, err)
	payload := []byte{}
	for _, po := range m.Tbs.Payload {
		payload = append(payload, po.Content...)
	}
	require.Equal(t, payload, content)
}

func TestEncryptedMessage(t *testing.T) {
	ns, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ns.PublicDER,
	})
	ent, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ent.PublicDER,
	})

	attresp, err := am.wave.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ns.SecretDER,
			},
		},
		Publish:     true,
		SubjectHash: ent.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: ns.Hash,
				Statements: []*pb.RTreePolicyStatement{
					{
						PermissionSet: []byte(WAVEMQPermissionSet),
						Permissions:   []string{WAVEMQPublish},
						Resource:      "foo/bar",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)

	persp := &mqpb.Perspective{
		EntitySecret: &mqpb.EntitySecret{
			DER: ent.SecretDER,
		},
	}

	content := []byte("hello world")
	msg, err := am.FormMessage(&mqpb.PublishParams{
		Perspective:         persp,
		Namespace:           ns.Hash,
		Uri:                 "foo/bar",
		Content:             []*mqpb.PayloadObject{{Schema: "text", Content: content}},
		EncryptionPartition: [][]byte{[]byte("foo"), []byte("bar")},
	}, "lol")
	require.NoError(t, err)

	//validate
	try1 := am.CheckMessage(persp, msg)
	require.NoError(t, try1)
	try2 := am.DRCheckMessage(msg)
	require.Error(t, try2)

	wavepersp := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: ns.SecretDER,
		},
	}
	am.provisionKey(wavepersp, ns.Hash)
	// validate
	try1 = am.DRCheckMessage(msg)
	require.NoError(t, try1)
	try2 = am.DRCheckMessage(msg)
	require.NoError(t, try2)

	// prepare
	m, err := am.PrepareMessage(persp, msg)
	require.Error(t, err)

	attresp, err = am.wave.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ns.SecretDER,
			},
		},
		Publish:     true,
		SubjectHash: ent.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: ns.Hash,
				Statements: []*pb.RTreePolicyStatement{
					{
						PermissionSet: []byte(consts.WaveBuiltinPSET),
						Permissions:   []string{consts.WaveBuiltinE2EE},
						Resource:      "foo/bar",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)

	m, err = am.PrepareMessage(persp, msg)
	require.NoError(t, err)
	payload := []byte{}
	for _, po := range m.Tbs.Payload {
		payload = append(payload, po.Content...)
	}
	require.Equal(t, payload, content)
}

func BenchmarkCheckMessage(t *testing.B) {
	ns, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ns.PublicDER,
	})
	ent, err := am.wave.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	require.NoError(t, err)
	am.wave.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: ent.PublicDER,
	})
	attresp, err := am.wave.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ns.SecretDER,
			},
		},
		Publish:     true,
		SubjectHash: ent.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: ns.Hash,
				Statements: []*pb.RTreePolicyStatement{
					{
						PermissionSet: []byte(WAVEMQPermissionSet),
						Permissions:   []string{WAVEMQPublish},
						Resource:      "foo/bar",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)

	attresp, err = am.wave.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ns.SecretDER,
			},
		},
		Publish:     true,
		SubjectHash: ent.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: ns.Hash,
				Statements: []*pb.RTreePolicyStatement{
					{
						PermissionSet: []byte(consts.WaveBuiltinPSET),
						Permissions:   []string{consts.WaveBuiltinE2EE},
						Resource:      WAVEMQUri,
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)

	persp := &mqpb.Perspective{
		EntitySecret: &mqpb.EntitySecret{
			DER: ent.SecretDER,
		},
	}
	msg, err := am.FormMessage(&mqpb.PublishParams{
		Perspective: persp,
		Namespace:   ns.Hash,
		Uri:         "foo/bar",
	}, "lol")
	require.NoError(t, err)

	// proofresp, err := am.wave.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
	// 	Perspective: wavepersp,
	// 	Namespace:   ns.Hash,
	// 	Statements: []*pb.RTreePolicyStatement{
	// 		{
	// 			PermissionSet: []byte(WAVEMQPermissionSet),
	// 			Permissions:   []string{WAVEMQPublish},
	// 			Resource:      "foo/bar",
	// 		},
	// 	},
	// 	ResyncFirst: true,
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// if proofresp.Error != nil {
	// 	panic(proofresp.Error.Message)
	// }
	// fmt.Println("this is the proof from benchmark")
	// fmt.Println(string(proofresp.ProofDER[:32]))
	// fmt.Println("the hash")
	// h := sha256.New()
	// h.Write(proofresp.ProofDER)
	// fmt.Println(string(h.Sum(nil)))
	// resp, err := am.wave.VerifyProof(context.Background(), &pb.VerifyProofParams{
	// 	ProofDER: proofresp.ProofDER,
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// if resp.Error != nil {
	// 	panic(resp.Error.Message)
	// }
	// encresp, err := am.wave.EncryptMessage(context.Background(), &pb.EncryptMessageParams{
	// 	Namespace: ns.Hash,
	// 	Resource:  WAVEMQUri,
	// 	Content:   proofresp.ProofDER,
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// if encresp.Error != nil {
	// 	panic(encresp.Error.Message)
	// }
	// fmt.Println("this is the ciphertext from benchmark")
	// fmt.Println(string(encresp.Ciphertext[:64]))
	wavepersp := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER:        ent.SecretDER,
			Passphrase: nil,
		},
	}
	am.provisionKey(wavepersp, msg.Tbs.ProofDER)
	t.ResetTimer()
	fmt.Printf("===== BEGIN <<<<\n")
	for i := 0; i < t.N; i++ {
		//validate
		try1 := am.CheckMessage(persp, msg)
		require.NoError(t, try1)
	}
	fmt.Printf("===== END >>>>>>\n")
}
