using Data.Actions.Notify.SoundElements;

namespace DamageMeter.UI
{
    public class TtsDataVM : BaseSoundVM
    {
        private readonly TextToSpeech _tts;
        private bool _enabled;
        private string _text;
        private VoiceGender _gender;
        private VoiceAge _age;
        private int _voiceIndex;
        private string _culture;
        private int _volume; //0-100
        private int _rate;

        public bool Enabled
        {
            get => _enabled;
            set
            {
                if (_enabled == value) return;
                _enabled = value;
                _tts.Enabled = value;
                NotifyPropertyChanged();
            }
        }

        public string Text
        {
            get => _text;
            set
            {
                if (_text == value) return;
                _text = value;
                _tts.Text = value;
                NotifyPropertyChanged();
            }
        }

        public VoiceGender Gender
        {
            get => _gender;
            set
            {
                if (_gender == value) return;
                _gender = value;
                _tts.VoiceGender = value;
                NotifyPropertyChanged();
            }
        }

        public VoiceAge Age
        {
            get => _age;
            set
            {
                if (_age == value) return;
                _age = value;
                _tts.VoiceAge = value;
                NotifyPropertyChanged();
            }
        }

        public int VoiceIndex
        {
            get => _voiceIndex;
            set
            {
                if (_voiceIndex == value) return;
                _voiceIndex = value;
                _tts.VoicePosition = value;
                NotifyPropertyChanged();
            }
        }

        public string Culture
        {
            get => _culture;
            set
            {
                if (_culture == value) return;
                _culture = value;
                _tts.CultureInfo = value;
                NotifyPropertyChanged();
            }
        }

        public int Volume
        {
            get => _volume;
            set
            {
                if (_volume == value) return;
                _volume = value;
                _tts.Volume = value;
                NotifyPropertyChanged();
            }
        }

        public int Rate
        {
            get => _rate;
            set
            {
                if (_rate == value) return;
                _rate = value;
                _tts.Rate = value;
                NotifyPropertyChanged();
            }
        }

        public TtsDataVM(TextToSpeech tts)
        {
            _tts = tts;
            _enabled = tts.Enabled;
            _text = tts.Text;
            _gender = tts.VoiceGender;
            _age = tts.VoiceAge;
            _voiceIndex = tts.VoicePosition;
            _culture = tts.CultureInfo;
            _volume = tts.Volume;
            _rate = tts.Rate;
        }
    }
}
