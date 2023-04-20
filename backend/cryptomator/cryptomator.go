package cryptomator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/cache"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/hash"

	"github.com/fhilgers/gocryptomator/pkg/vault"
)

func init() {
	fs.Register(&fs.RegInfo{
		Name:        "cryptomator",
		Description: "Treat a remote as Cryptomator Vault",
		NewFs:       NewFs,
    MetadataInfo: &fs.MetadataInfo{
      Help: `Any metadata supported by the underlying remote is read and written`,
    },
		Options: []fs.Option{
			{
				Name:     "remote",
				Help:     "Remote which contains the Cryptomator Vault",
				Required: true,
			},
			{
				Name:       "password",
				Help:       "Password for the Cryptomator Vault",
				IsPassword: true,
				Required:   true,
			},
		},
	})
}

type Options struct {
	Remote   string `config:"remote"`
	Password string `config:"password"`
}

type Fs struct {
  fs         fs.Fs
	name       string
	root       string
	vault      *vault.Vault
	features   *fs.Features
}

func newOpts(m configmap.Mapper) (*Options, error) {
	opts := new(Options)
	err := configstruct.Set(m, opts)
	return opts, err
}


func NewFs(ctx context.Context, name, rpath string, m configmap.Mapper) (fs.Fs, error) {
	opts, err := newOpts(m)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(opts.Remote, name+":") {
		return nil, errors.New("can't point cryptomator remote at itself")
	}

	rootFs, err := cache.Get(ctx, opts.Remote)
	if err != nil {
		return nil, err
	}

	vaultFs := &VaultFs{
    f: rootFs,
    ctx: ctx,
	}

	password, err := obscure.Reveal(opts.Password)
	if err != nil {
		return nil, err
	}

  v, err := vault.Open(vaultFs, password)
  if err != nil {
    v, err = vault.Create(vaultFs, password)
    if err != nil {
      return nil, fmt.Errorf("failed to unlock vault: %w", err)
    }
  }

	var fsErr error
  if filePath, err := v.GetFilePath(rpath); err == nil {
    if exists, err := fs.FileExists(ctx, rootFs, filePath); exists {
			rpath = path.Dir(rpath)
			fsErr = fs.ErrorIsFile
    } else if err != nil {
      return nil, err
    }
  }

	f := &Fs{
		name:       name,
		root:       rpath,
		vault:      v,
    fs: rootFs,
	}

	cache.PinUntilFinalized(rootFs, f)

	f.features = (&fs.Features{
    CaseInsensitive: false,
    DuplicateFiles: true,
    BucketBased: true,
		CanHaveEmptyDirectories: true,
    SetTier: true,
    GetTier: true,
    ReadMetadata: true,
    WriteMetadata: true,
    UserMetadata: true,
    WriteMimeType: false,
    ReadMimeType: false,
	}).Fill(ctx, f).Mask(ctx, rootFs).WrapsFs(f, rootFs)

	return f, fsErr
}

func (f *Fs) Name() string {
	return f.name
}

func (f *Fs) Root() string {
	return f.root
}

func (f *Fs) String() string {
	return fmt.Sprintf("Cryptomator vault '%s:%s'", f.Name(), f.Root())
}

func (f *Fs) Precision() time.Duration {
	return f.fs.Precision()
}

func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.None)
}

func (f *Fs) Features() *fs.Features {
	return f.features
}

func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
  path, err := f.vault.GetDirPath(f.fullPath(dir))
  if err != nil {
    return nil, fs.ErrorDirNotFound
  }

  entries, err := f.fs.List(ctx, path)
  if err != nil {
    return nil, err
  }


  return f.wrapEntries(entries, dir)
}

func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	fullPath := f.fullPath(remote)
  objPath, err := f.vault.GetFilePath(fullPath)
  if err != nil {
    return nil, err
  }

  obj, err := f.fs.NewObject(ctx, objPath)
  if err != nil {
    return nil, err
  }

  return f.newObject(obj, path.Dir(remote))
}

func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (obj fs.Object, err error) {
	fullPath := f.fullPath(src.Remote())
	if err = f.Mkdir(ctx, filepath.Dir(src.Remote())); err != nil {
		return
	}

	objPath, err := f.vault.GetFilePath(fullPath)
	if err != nil {
		return
	}

  encReader, err := f.vault.NewEncryptReader(in)
  if err != nil {
    return nil, err
  }

  info := f.newEncryptedObjectInfo(src, objPath)
  //info := object.NewStaticObjectInfo(objPath, src.ModTime(ctx), vault.CalculateEncryptedFileSize(src.Size()), src.Storable(), nil, f)

  obj, err = f.fs.Put(ctx, encReader, info, options...)
  if err != nil {
    return nil, err
  }

  return f.newObject(obj, path.Dir(src.Remote()))
}

func (f *Fs) Mkdir(ctx context.Context, dir string) error {
  fullPath := f.fullPath(dir)
  fullPath = path.Clean(fullPath)
  if fullPath == "." {
    fullPath = ""
  }

  segments := strings.Split(fullPath, "/")
  for i := range segments {
    if err := f.vault.Mkdir(strings.Join(segments[:i + 1], "/")); err != nil {
      return err
    }
  }

  return nil
}

func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return f.vault.Rmdir(f.fullPath(dir))
}

func (f *Fs) newObject(obj fs.Object, dir string) (*Object, error) {
  dirID, err := f.vault.GetDirID(f.fullPath(dir))
  if err != nil {
    return nil, err
  }

  encName := path.Base(obj.Remote())
  decName, err := f.vault.DecryptFileName(encName, dirID)
  if err != nil {
    return nil, err
  }

	return &Object{
    Object: obj,
    remote: path.Join(dir, decName),
    size: vault.CalculateRawFileSize(obj.Size()),
		f:          f,
  }, nil
}

func (f *Fs) newDirectory(d fs.Directory, dir string) (*Directory, error) {
  dirID, err := f.vault.GetDirID(f.fullPath(dir))
  if err != nil {
    return nil, err
  }

  encName := path.Base(d.Remote())
  decName, err := f.vault.DecryptFileName(encName, dirID)
  if err != nil {
    return nil, err
  }

  return &Directory{
    remote: path.Join(dir, decName),
    Directory: d,
  }, nil
}

func (f *Fs) newEncryptedObjectInfo(info fs.ObjectInfo, remote string) (*EncryptedObjectInfo) {
  return &EncryptedObjectInfo{
    ObjectInfo: info,
    remote: remote,
    size: vault.CalculateEncryptedFileSize(info.Size()),
  }
}


func (f *Fs) fullPath(path string) string {
	return filepath.Join(f.root, path)
}

func (f *Fs) wrapEntries(entries fs.DirEntries, dir string) (wrappedEntries fs.DirEntries, err error) {
	var wrappedEntry fs.DirEntry
	for _, entry := range entries {
    switch x := entry.(type) {
    case fs.Object:
      if path.Base(x.Remote()) == "dirid.c9r" {
        continue
      }
      wrappedEntry, err = f.newObject(x, dir)
    case fs.Directory:
      wrappedEntry, err = f.newDirectory(x, dir)
	  }

    if err != nil {
      return
    }

		wrappedEntries = append(wrappedEntries, wrappedEntry)
  }

	return
}


type Directory struct {
  fs.Directory
  remote string
}

func (d *Directory) String() string {
  return d.remote
}

func (d *Directory) Remote() string {
  return d.remote
}

func (d *Directory) Items() int64 {
  // We dont know the real amount and would have to call list again
	return -1
}

type EncryptedObjectInfo struct {
  fs.ObjectInfo

  remote string
  size int64
}

func (i *EncryptedObjectInfo) Remote() string {
  return i.remote
}
func (i *EncryptedObjectInfo) String() string {
  return i.remote
}

func (i *EncryptedObjectInfo) Size() int64 {
  return i.size
}

func (i *EncryptedObjectInfo) Metadata(ctx context.Context) (fs.Metadata, error) {
  do, ok := i.ObjectInfo.(fs.Metadataer)
  if !ok {
    return nil, nil
  }
  return do.Metadata(ctx)
}


type Object struct {
  fs.Object

	f *Fs

  remote string
  size int64
}

func (o *Object) String() string {
  return o.remote
}

func (o *Object) Remote() string {
  return o.remote
}

func (o *Object) Size() int64 {
  return o.size
}

func (o *Object) Fs() fs.Info {
  return o.f
}

func (o *Object) Metadata(ctx context.Context) (fs.Metadata, error) {
  do, ok := o.Object.(fs.Metadataer)
  if !ok {
    return nil, nil
  }
  return do.Metadata(ctx)
}

func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
  return "", hash.ErrUnsupported
}


func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	var offset, limit int64 = 0, -1
	var openOptions []fs.OpenOption
	for _, option := range options {
		switch x := option.(type) {
		case *fs.SeekOption:
			offset = x.Offset
		case *fs.RangeOption:
			offset, limit = x.Decode(o.Size())
		default:
			openOptions = append(openOptions, option)
		}
	}
	//TODO handle openOptions

  readCloser, err := o.Object.Open(ctx, openOptions...)
  if err != nil {
    return nil, err
  }

  decReader, err := o.f.vault.NewDecryptReader(readCloser)
  if err != nil {
    return nil, err
  }

  if offset > 0 {
    _, err := io.CopyN(io.Discard, decReader, offset)
    if err != nil {
      return nil, err
    }
  }

  if limit != -1 {
    return readCloseWrapper{
      Reader: io.LimitReader(decReader, limit),
      Closer: readCloser,
    }, nil
  }

  return readCloseWrapper{
    Reader: decReader,
    Closer: readCloser,
  }, nil
}

func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	fullPath := o.f.fullPath(src.Remote())

	objPath, err := o.f.vault.GetFilePath(fullPath)
	if err != nil {
		return nil
	}

  encReader, err := o.f.vault.NewEncryptReader(in)
  if err != nil {
    return err
  }

  info := o.f.newEncryptedObjectInfo(src, objPath)
  //info := object.NewStaticObjectInfo(objPath, src.ModTime(ctx), vault.CalculateEncryptedFileSize(src.Size()), src.Storable(), nil, o.f)

  o.size = src.Size()

  return o.Object.Update(ctx, encReader, info, options...)
}


type readCloseWrapper struct {
	io.Reader
	io.Closer
}



var (
  _ fs.Fs = (*Fs)(nil)
  _ fs.Object = (*Object)(nil)
  _ fs.Directory = (*Directory)(nil)
)
